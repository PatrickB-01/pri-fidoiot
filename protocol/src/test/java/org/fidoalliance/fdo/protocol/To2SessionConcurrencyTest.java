package org.fidoalliance.fdo.protocol;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class To2SessionConcurrencyTest {
  @Test
  public void creatingAnotherSessionDoesNotWaitForAnActiveSession() throws Exception {
    checkConcurrentExpiry(false);
  }

  @Test
  public void expiredBusySessionsDoNotBlockCreationOrPrematurelyDestroyActiveWork() throws Exception {
    checkConcurrentExpiry(true);
  }

  private void checkConcurrentExpiry(boolean expire) throws Exception {
    AtomicLong clock = new AtomicLong();
    AtomicInteger destroyed = new AtomicInteger();
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    ExecutorService workers = Executors.newFixedThreadPool(2);
    try (To2SessionStore<AutoCloseable> store = new To2SessionStore<>(2, 50, clock::get)) {
      String active = store.create(destroyed::incrementAndGet);
      Future<Boolean> operation = workers.submit(() -> store.execute(active, value -> {
        entered.countDown();
        try {
          if (!release.await(5, TimeUnit.SECONDS)) {
            throw new IOException("test operation not released");
          }
        } catch (InterruptedException exception) {
          Thread.currentThread().interrupt();
          throw new IOException(exception);
        }
        return true;
      }));
      Assertions.assertTrue(entered.await(2, TimeUnit.SECONDS));
      if (expire) {
        clock.set(50);
      }
      Future<String> unrelated = workers.submit(() -> {
        store.expire();
        return store.create(destroyed::incrementAndGet);
      });
      try {
        String second = unrelated.get(1, TimeUnit.SECONDS);
        Assertions.assertNotEquals(active, second);
        Assertions.assertEquals(0, destroyed.get());
        Assertions.assertThrows(IOException.class, () -> store.create(() -> { }));
      } finally {
        release.countDown();
      }
      Assertions.assertTrue(operation.get(2, TimeUnit.SECONDS));
      store.expire();
      Assertions.assertEquals(expire ? 1 : 0, destroyed.get());
      if (expire) {
        Assertions.assertThrows(IOException.class, () -> store.execute(active, value -> true));
      } else {
        Assertions.assertEquals(Boolean.TRUE, store.execute(active, value -> true));
      }
    } finally {
      release.countDown();
      workers.shutdownNow();
    }
    Assertions.assertEquals(2, destroyed.get());
  }
}
