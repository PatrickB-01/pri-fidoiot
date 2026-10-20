package org.fidoalliance.fdo.protocol;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

public class To2MlKemPoolTest {
  private To2MlKemPool fake(String mode, long timeout) {
    String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    String classpath = System.getProperty("surefire.test.class.path",
        System.getProperty("java.class.path"));
    return new To2MlKemPool(List.of(java, "-Xmx32m", "-XX:+UseSerialGC",
        "-XX:ActiveProcessorCount=1", "-cp", classpath, FakeWorker.class.getName(), mode),
        1, timeout);
  }

  @Test
  public void malformedFramesFailClosedWithoutAllocatingUnboundedBodies() throws Exception {
    for (String mode : List.of("wrong-operation", "oversize", "truncated")) {
      try (To2MlKemPool pool = fake(mode, 3000)) {
        To2MlKemPool.Failure failure = Assertions.assertThrows(To2MlKemPool.Failure.class,
            () -> pool.execute("keygen", new byte[0], 3584));
        Assertions.assertEquals(mode.equals("truncated") ? To2MlKemPool.Reason.IO
            : To2MlKemPool.Reason.PROTOCOL, failure.reason);
        Assertions.assertTrue(pool.processIds().isEmpty());
      }
    }
  }

  @Test
  public void timeoutsKillStalledWorkersAndDoNotWaitForUnboundedPipeReads() throws Exception {
    try (To2MlKemPool pool = fake("hang", 750)) {
      long started = System.nanoTime();
      To2MlKemPool.Failure failure = Assertions.assertThrows(To2MlKemPool.Failure.class,
          () -> pool.execute("keygen", new byte[0], 3584));
      Assertions.assertEquals(To2MlKemPool.Reason.TIMEOUT, failure.reason);
      Assertions.assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(3));
      Assertions.assertTrue(pool.processIds().isEmpty());
    }

  }

  @Test
  public void queueWaitingAndPipeExecutionShareOneDeadline() throws Exception {
    ExecutorService callers = Executors.newSingleThreadExecutor();
    try (To2MlKemPool pool = fake("hang", 750)) {
      Future<To2MlKemPool.Failure> first = callers.submit(() ->
          Assertions.assertThrows(To2MlKemPool.Failure.class,
              () -> pool.execute("keygen", new byte[0], 3584)));
      long waitUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
      while (pool.processIds().isEmpty() && System.nanoTime() < waitUntil) {
        Thread.sleep(5);
      }
      Assertions.assertFalse(pool.processIds().isEmpty());
      long started = System.nanoTime();
      To2MlKemPool.Failure queued = Assertions.assertThrows(To2MlKemPool.Failure.class,
          () -> pool.execute("keygen", new byte[0], 3584));
      Assertions.assertTrue(queued.reason == To2MlKemPool.Reason.CAPACITY
          || queued.reason == To2MlKemPool.Reason.TIMEOUT);
      Assertions.assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2));
      Assertions.assertEquals(To2MlKemPool.Reason.TIMEOUT, first.get(2, TimeUnit.SECONDS).reason);
    } finally {
      callers.shutdownNow();
    }
  }

  @Test
  public void interruptedCallersPreserveInterruptStatusAndStopTheirWorker() throws Exception {
    try (To2MlKemPool pool = fake("hang", 3000)) {
      AtomicReference<IOException> failure = new AtomicReference<>();
      AtomicBoolean interrupted = new AtomicBoolean();
      CountDownLatch finished = new CountDownLatch(1);
      Thread caller = new Thread(() -> {
        try {
          pool.execute("keygen", new byte[0], 3584);
        } catch (IOException exception) {
          failure.set(exception);
          interrupted.set(Thread.currentThread().isInterrupted());
        } finally {
          finished.countDown();
        }
      });
      caller.start();
      try {
        long waitUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (pool.processIds().isEmpty() && System.nanoTime() < waitUntil) {
          Thread.sleep(5);
        }
        Assertions.assertFalse(pool.processIds().isEmpty());
        caller.interrupt();
        Assertions.assertTrue(finished.await(2, TimeUnit.SECONDS));
        Assertions.assertInstanceOf(To2MlKemPool.Failure.class, failure.get());
        Assertions.assertEquals(To2MlKemPool.Reason.INTERRUPTED,
            ((To2MlKemPool.Failure) failure.get()).reason);
        Assertions.assertTrue(interrupted.get());
        Assertions.assertTrue(pool.processIds().isEmpty());
      } finally {
        caller.interrupt();
        caller.join(2000);
      }
    }
  }

  @Test
  public void rejectedInputsDoNotPoisonTheNextResponseOrRestartAHealthyWorker() throws Exception {
    try (To2MlKemPool pool = fake("reject-once", 3000)) {
      To2MlKemPool.Failure failure = Assertions.assertThrows(To2MlKemPool.Failure.class,
          () -> pool.execute("keygen", new byte[0], 3584));
      Assertions.assertEquals(To2MlKemPool.Reason.REJECTED, failure.reason);
      List<Long> before = pool.processIds();
      Assertions.assertEquals(1, before.size());
      byte[] result = pool.execute("keygen", new byte[0], 3584);
      Assertions.assertEquals(3584, result.length);
      Assertions.assertEquals(before, pool.processIds());
      Arrays.fill(result, (byte) 0);
    }
  }

  @Test
  public void deadWorkersAreReplacedAndClosingRejectsFurtherOperations() throws Exception {
    To2MlKemPool pool = fake("normal", 3000);
    List<Long> pids;
    try {
      Arrays.fill(pool.execute("keygen", new byte[0], 3584), (byte) 0);
      long old = pool.processIds().get(0);
      ProcessHandle process = ProcessHandle.of(old).orElseThrow();
      process.destroyForcibly();
      process.onExit().get(2, TimeUnit.SECONDS);
      Arrays.fill(pool.execute("keygen", new byte[0], 3584), (byte) 0);
      pids = pool.processIds();
      Assertions.assertNotEquals(old, pids.get(0));
    } finally {
      pool.close();
    }
    for (long pid : pids) {
      if (ProcessHandle.of(pid).isPresent()) {
        ProcessHandle.of(pid).orElseThrow().onExit().get(2, TimeUnit.SECONDS);
      }
    }
    To2MlKemPool.Failure failure = Assertions.assertThrows(To2MlKemPool.Failure.class,
        () -> pool.execute("keygen", new byte[0], 3584));
    Assertions.assertEquals(To2MlKemPool.Reason.CLOSED, failure.reason);
  }

  @Test
  public void thirtyTwoConcurrentRealOperationsReuseOnlyTwoJvmsAndUseFreshRandomness()
      throws Exception {
    String directory = System.getProperty("to2.pq.provider.directory");
    Assumptions.assumeTrue(directory != null, "container-built provider required");
    ExecutorService callers = Executors.newFixedThreadPool(32);
    byte[] pair = null;
    try (To2MlKemPool pool = new To2MlKemPool(Path.of(directory))) {
      pair = pool.execute("keygen", new byte[0], 3584);
      byte[] publicKey = Arrays.copyOf(pair, 1184);
      Arrays.fill(pool.execute("encaps", publicKey, 1120), (byte) 0);
      List<Long> initial = pool.processIds();
      Assertions.assertEquals(2, initial.size());
      List<Future<byte[]>> pending = new ArrayList<>();
      for (int index = 0; index < 32; index++) {
        pending.add(callers.submit(() -> pool.execute("encaps", publicKey, 1120)));
      }
      Set<String> ciphertexts = new HashSet<>();
      for (Future<byte[]> future : pending) {
        byte[] encapsulated = future.get(15, TimeUnit.SECONDS);
        byte[] input = new byte[3488];
        System.arraycopy(pair, 1184, input, 0, 2400);
        System.arraycopy(encapsulated, 0, input, 2400, 1088);
        byte[] secret = pool.execute("decaps", input, 32);
        try {
          Assertions.assertArrayEquals(Arrays.copyOfRange(encapsulated, 1088, 1120), secret);
          Assertions.assertTrue(ciphertexts.add(java.util.Base64.getEncoder().encodeToString(
              MessageDigest.getInstance("SHA-256").digest(Arrays.copyOf(encapsulated, 1088)))));
        } finally {
          Arrays.fill(secret, (byte) 0);
          Arrays.fill(input, (byte) 0);
          Arrays.fill(encapsulated, (byte) 0);
        }
      }
      Assertions.assertEquals(initial, pool.processIds());
      byte[] invalid = new byte[1184];
      Arrays.fill(invalid, (byte) 255);
      To2MlKemPool.Failure rejected = Assertions.assertThrows(To2MlKemPool.Failure.class,
          () -> pool.execute("encaps", invalid, 1120));
      Assertions.assertEquals(To2MlKemPool.Reason.REJECTED, rejected.reason);
      Arrays.fill(pool.execute("encaps", publicKey, 1120), (byte) 0);
      Assertions.assertEquals(initial, pool.processIds());
    } finally {
      if (pair != null) {
        Arrays.fill(pair, (byte) 0);
      }
      callers.shutdownNow();
    }
  }

  public static final class FakeWorker {
    public static void main(String[] args) throws Exception {
      DataInputStream input = new DataInputStream(System.in);
      DataOutputStream output = new DataOutputStream(System.out);
      output.writeInt(To2MlKemPool.READY);
      output.flush();
      int requests = 0;
      while (true) {
        int operation = input.readInt();
        byte[] body = new byte[input.readInt()];
        input.readFully(body);
        Arrays.fill(body, (byte) 0);
        if (args[0].equals("hang")) {
          Thread.sleep(10000);
        }
        boolean rejected = args[0].equals("reject-once") && requests++ == 0;
        output.writeInt(args[0].equals("wrong-operation") ? operation + 1 : operation);
        output.writeInt(rejected ? 1 : 0);
        output.writeInt(rejected ? 0 : args[0].equals("oversize") ? Integer.MAX_VALUE : 3584);
        if (!rejected && !args[0].equals("oversize")) {
          output.write(new byte[args[0].equals("truncated") ? 16 : 3584]);
        }
        output.flush();
        if (args[0].equals("truncated")) {
          return;
        }
      }
    }
  }
}
