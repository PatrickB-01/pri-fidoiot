package org.fidoalliance.fdo.protocol;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;

final class To2MlKemPool implements AutoCloseable {
  static final int READY = 0x4d4c4b31;
  static final int WORKERS = 2;
  private static final long TIMEOUT_MILLIS = 10000;

  enum Reason {
    CAPACITY, TIMEOUT, INTERRUPTED, CLOSED, IO, PROTOCOL, REJECTED
  }

  static final class Failure extends IOException {
    final Reason reason;

    Failure(Reason reason) {
      super("ML-KEM worker " + reason.name().toLowerCase(java.util.Locale.ROOT));
      this.reason = reason;
    }

    String category() {
      return "pq-worker-" + reason.name().toLowerCase(java.util.Locale.ROOT);
    }
  }

  private final class Worker {
    private final AtomicLong generation = new AtomicLong();
    private volatile Process process;
    private final ThreadPoolExecutor io;

    Worker(int index) {
      io = new ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS,
          new ArrayBlockingQueue<>(1), task -> {
        Thread thread = new Thread(task, "to2-pq-io-" + index);
        thread.setDaemon(true);
        return thread;
      });
    }

    byte[] exchange(int operation, byte[] input, int expected, long version) throws IOException {
      if (closed || generation.get() != version) {
        throw new Failure(Reason.CLOSED);
      }
      Process current = process;
      if (current == null || !current.isAlive()) {
        current = new ProcessBuilder(command)
            .redirectError(ProcessBuilder.Redirect.INHERIT).start();
        process = current;
        if (closed || generation.get() != version) {
          current.destroyForcibly();
          if (process == current) {
            process = null;
          }
          throw new Failure(Reason.CLOSED);
        }
        if (new DataInputStream(current.getInputStream()).readInt() != READY) {
          throw new Failure(Reason.PROTOCOL);
        }
      }
      DataOutputStream output = new DataOutputStream(current.getOutputStream());
      output.writeInt(operation);
      output.writeInt(input.length);
      output.write(input);
      output.flush();
      DataInputStream response = new DataInputStream(current.getInputStream());
      int actual = response.readInt();
      int status = response.readInt();
      int length = response.readInt();
      if (actual != operation || (status != 0 && status != 1)
          || length != (status == 0 ? expected : 0)) {
        throw new Failure(Reason.PROTOCOL);
      }
      if (status == 1) {
        throw new Failure(Reason.REJECTED);
      }
      byte[] result = new byte[expected];
      try {
        response.readFully(result);
        return result;
      } catch (IOException exception) {
        Arrays.fill(result, (byte) 0);
        throw exception;
      }
    }

    void stop() {
      generation.incrementAndGet();
      Process current = process;
      process = null;
      if (current != null) {
        current.destroyForcibly();
      }
    }
  }

  private final class Exchange implements Callable<Void> {
    private final Worker worker;
    private final int operation;
    private final byte[] input;
    private final int expected;
    private final long generation;
    private byte[] result;
    private boolean abandoned;

    Exchange(Worker worker, int operation, byte[] input, int expected) {
      this.worker = worker;
      this.operation = operation;
      this.input = input.clone();
      this.expected = expected;
      generation = worker.generation.get();
    }

    @Override
    public Void call() throws IOException {
      try {
        byte[] value = worker.exchange(operation, input, expected, generation);
        synchronized (this) {
          if (abandoned) {
            Arrays.fill(value, (byte) 0);
          } else {
            result = value;
          }
        }
        return null;
      } finally {
        Arrays.fill(input, (byte) 0);
      }
    }

    synchronized byte[] take() throws IOException {
      if (result == null || abandoned) {
        throw new Failure(Reason.PROTOCOL);
      }
      byte[] value = result;
      result = null;
      return value;
    }

    synchronized void abandon() {
      abandoned = true;
      Arrays.fill(input, (byte) 0);
      if (result != null) {
        Arrays.fill(result, (byte) 0);
        result = null;
      }
    }
  }

  private final List<String> command;
  private final List<Worker> workers = new ArrayList<>();
  private final ArrayBlockingQueue<Worker> available;
  private final long timeoutNanos;
  private volatile boolean closed;

  To2MlKemPool(Path directory) {
    this(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
        "-Xmx32m", "-Xss256k", "-XX:ActiveProcessorCount=1", "-XX:+UseSerialGC",
        "-cp", directory + java.io.File.pathSeparator + directory.resolve("bcprov.jar"),
        "MlKemProvider", "serve"), WORKERS, TIMEOUT_MILLIS);
  }

  To2MlKemPool(List<String> command, int size, long timeoutMillis) {
    if (size < 1 || size > WORKERS || timeoutMillis <= 0 || timeoutMillis > TIMEOUT_MILLIS) {
      throw new IllegalArgumentException("invalid ML-KEM worker bounds");
    }
    this.command = List.copyOf(command);
    timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
    available = new ArrayBlockingQueue<>(size);
    for (int index = 0; index < size; index++) {
      Worker worker = new Worker(index);
      workers.add(worker);
      available.add(worker);
    }
  }

  byte[] execute(String operation, byte[] input, int expected) throws IOException {
    int number;
    int inputLength;
    int outputLength;
    switch (operation) {
      case "keygen":
        number = 1;
        inputLength = 0;
        outputLength = 3584;
        break;
      case "encaps":
        number = 2;
        inputLength = 1184;
        outputLength = 1120;
        break;
      case "decaps":
        number = 3;
        inputLength = 3488;
        outputLength = 32;
        break;
      default:
        throw new Failure(Reason.REJECTED);
    }
    if (input.length != inputLength || expected != outputLength) {
      throw new Failure(Reason.REJECTED);
    }
    long deadline = System.nanoTime() + timeoutNanos;
    Worker worker = null;
    Exchange exchange = null;
    Future<Void> future = null;
    boolean healthy = false;
    try {
      if (closed) {
        throw new Failure(Reason.CLOSED);
      }
      while (worker == null && !closed) {
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
          throw new Failure(Reason.CAPACITY);
        }
        worker = available.poll(Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(100)),
            TimeUnit.NANOSECONDS);
      }
      if (closed) {
        throw new Failure(Reason.CLOSED);
      }
      exchange = new Exchange(worker, number, input, expected);
      future = worker.io.submit(exchange);
      long remaining = deadline - System.nanoTime();
      if (remaining <= 0) {
        throw new Failure(Reason.TIMEOUT);
      }
      future.get(remaining, TimeUnit.NANOSECONDS);
      byte[] result = exchange.take();
      healthy = true;
      return result;
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      throw new Failure(Reason.INTERRUPTED);
    } catch (TimeoutException exception) {
      throw new Failure(Reason.TIMEOUT);
    } catch (CancellationException exception) {
      throw new Failure(closed ? Reason.CLOSED : Reason.INTERRUPTED);
    } catch (RejectedExecutionException exception) {
      throw new Failure(closed ? Reason.CLOSED : Reason.CAPACITY);
    } catch (ExecutionException exception) {
      if (exception.getCause() instanceof Failure) {
        Failure failure = (Failure) exception.getCause();
        healthy = failure.reason == Reason.REJECTED;
        throw failure;
      }
      throw new Failure(Reason.IO);
    } finally {
      if (exchange != null) {
        exchange.abandon();
      }
      if (worker != null) {
        if (!healthy) {
          worker.stop();
          if (future != null) {
            future.cancel(true);
          }
          worker.io.purge();
        }
        if (!closed && !available.offer(worker)) {
          worker.stop();
          throw new IllegalStateException("ML-KEM worker returned twice");
        }
      }
    }
  }

  List<Long> processIds() {
    List<Long> result = new ArrayList<>();
    for (Worker worker : workers) {
      Process process = worker.process;
      if (process != null && process.isAlive()) {
        result.add(process.pid());
      }
    }
    return result;
  }

  @Override
  public void close() {
    closed = true;
    for (Worker worker : workers) {
      worker.stop();
      worker.io.shutdownNow();
    }
    available.clear();
  }
}
