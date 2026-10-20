package org.fidoalliance.fdo.protocol;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

public final class To2SessionStore<T extends AutoCloseable> implements AutoCloseable {

  @FunctionalInterface
  public interface Operation<T, R> {
    R apply(T session) throws IOException;
  }

  private final class Entry {
    private final T value;
    private volatile long deadline;
    private final ReentrantLock lock = new ReentrantLock();
    private boolean closed;

    private Entry(T value) {
      this.value = value;
      this.deadline = clock.getAsLong() + ttl;
    }

    private void destroy() {
      if (!closed) {
        closed = true;
        try {
          value.close();
        } catch (Exception ignored) {
          return;
        }
      }
    }
  }

  private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
  private final SecureRandom random = new SecureRandom();
  private final LongSupplier clock;
  private final long ttl;
  private final int capacity;
  private boolean closed;

  /**
   * Creates a store using an injected monotonic clock.
   *
   * @param capacity maximum live entries
   * @param ttl fixed lifetime in clock units
   * @param clock monotonic time source
   */
  public To2SessionStore(int capacity, long ttl, LongSupplier clock) {
    if (capacity < 1 || ttl < 1) {
      throw new IllegalArgumentException("invalid session limits");
    }
    this.capacity = capacity;
    this.ttl = ttl;
    this.clock = clock;
  }

  /**
   * Allocates a fresh token without taking ownership on failure.
   *
   * @param value session to own
   * @return opaque Authorization value
   * @throws IOException when capacity is unavailable
   */
  public synchronized String create(T value) throws IOException {
    expire();
    if (closed || entries.size() >= capacity) {
      throw new IOException("session capacity unavailable");
    }
    byte[] bytes = new byte[32];
    String token;
    do {
      random.nextBytes(bytes);
      token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    } while (entries.putIfAbsent(token, new Entry(value)) != null);
    return token;
  }

  /**
   * Executes under the individual session lock after checking its lifetime.
   *
   * @param token session lookup handle
   * @param operation action to execute
   * @param <R> result type
   * @return action result
   * @throws IOException on missing, expired or failed sessions
   */
  public <R> R execute(String token, Operation<T, R> operation) throws IOException {
    Entry entry = entries.get(token);
    if (entry == null) {
      throw new IOException("unknown session");
    }
    entry.lock.lock();
    try {
      if (entry.closed || entries.get(token) != entry
          || clock.getAsLong() - entry.deadline >= 0) {
        entries.remove(token, entry);
        entry.destroy();
        throw new IOException("expired session");
      }
      return operation.apply(entry.value);
    } finally {
      entry.lock.unlock();
    }
  }

  /**
   * Removes and destroys an entry exactly once.
   *
   * @param token session lookup handle
   */
  public void remove(String token) {
    Entry entry = entries.remove(token);
    if (entry != null) {
      entry.lock.lock();
      try {
        entry.destroy();
      } finally {
        entry.lock.unlock();
      }
    }
  }

  /** Evicts expired entries, including their private state. */
  public void expire() {
    entries.forEach((token, entry) -> {
      if (clock.getAsLong() - entry.deadline >= 0 && entry.lock.tryLock()) {
        try {
          if (clock.getAsLong() - entry.deadline >= 0 && entries.remove(token, entry)) {
            entry.destroy();
          }
        } finally {
          entry.lock.unlock();
        }
      }
    });
  }

  /**
   * Shortens an entry's remaining lifetime for terminal response caching.
   * @param token lookup handle
   * @param lifetime remaining lifetime in clock units
   */
  public void shorten(String token, long lifetime) {
    Entry entry = entries.get(token);
    if (entry != null) {
      entry.lock.lock();
      try {
        entry.deadline = Math.min(entry.deadline, clock.getAsLong() + lifetime);
      } finally {
        entry.lock.unlock();
      }
    }
  }

  @Override
  public synchronized void close() {
    closed = true;
    entries.keySet().forEach(this::remove);
  }
}