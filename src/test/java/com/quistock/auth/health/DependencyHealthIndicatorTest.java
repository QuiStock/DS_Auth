package com.quistock.auth.health;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

class DependencyHealthIndicatorTest {
  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void cachesResultAndAllowsCacheToBeDisabled() {
    AtomicInteger calls = new AtomicInteger();
    DependencyHealthIndicator indicator =
        new DependencyHealthIndicator(1000) {
          @Override
          protected boolean dependenciesAvailable() {
            return calls.incrementAndGet() == 1;
          }
        };
    indicator.configureCache(Duration.ofSeconds(5));
    try {
      assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
      assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
      assertThat(calls.get()).isEqualTo(1);
      indicator.configureCache(Duration.ZERO);
      assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
      assertThat(calls.get()).isEqualTo(2);
    } finally {
      indicator.shutdown();
    }
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void concurrentCallersShareCheckAfterTimeout() throws Exception {
    CountDownLatch started = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    AtomicInteger calls = new AtomicInteger();
    DependencyHealthIndicator indicator =
        new DependencyHealthIndicator(100) {
          @Override
          protected boolean dependenciesAvailable() throws InterruptedException {
            calls.incrementAndGet();
            started.countDown();
            release.await();
            return true;
          }
        };
    try (var callers = Executors.newFixedThreadPool(2)) {
      Callable<Health> healthCheck = indicator::health;
      var first = callers.submit(healthCheck);
      assertThat(started.await(1, TimeUnit.SECONDS)).isTrue();
      var second = callers.submit(healthCheck);
      assertThat(first.get(1, TimeUnit.SECONDS).getStatus()).isEqualTo(Status.DOWN);
      assertThat(second.get(1, TimeUnit.SECONDS).getStatus()).isEqualTo(Status.DOWN);
      assertThat(calls.get()).isEqualTo(1);
      release.countDown();
      assertThat(indicator.health().getStatus()).isEqualTo(Status.UP);
    } finally {
      release.countDown();
      indicator.shutdown();
    }
  }
}
