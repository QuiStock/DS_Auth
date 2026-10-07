package com.quistock.auth.health;

import jakarta.annotation.PreDestroy;
import java.io.IOException;
import java.sql.SQLException;
import java.text.ParseException;
import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/** Limits readiness latency and the number of blocked dependency checks. */
public abstract class DependencyHealthIndicator implements HealthIndicator {
  private static final Logger LOGGER = LoggerFactory.getLogger(DependencyHealthIndicator.class);
  private final long timeoutMs;
  private Check inFlight;
  private long cacheNanos;
  private final ThreadPoolExecutor executor =
      new ThreadPoolExecutor(
          0,
          2,
          30,
          TimeUnit.SECONDS,
          new SynchronousQueue<>(),
          Thread.ofPlatform().daemon().name("health-check-", 0).factory());

  protected DependencyHealthIndicator(long timeoutMs) {
    if (timeoutMs < 1 || timeoutMs > 30_000) {
      throw new IllegalArgumentException("HEALTH_TIMEOUT_MS must be between 1 and 30000.");
    }
    this.timeoutMs = timeoutMs;
  }

  @Autowired
  final void configureCache(
      @Value("${management.endpoint.health.cache.time-to-live:5s}") Duration cacheTtl) {
    if (cacheTtl.isNegative()) {
      throw new IllegalArgumentException("Health cache TTL must not be negative.");
    }
    cacheNanos = cacheTtl.toNanos();
  }

  @Override
  public Health health() {
    Check check;
    try {
      check = currentCheck();
    } catch (RejectedExecutionException exception) {
      LOGGER.warn("Health check capacity exhausted.");
      return Health.down().build();
    }
    try {
      return Boolean.TRUE.equals(check.task().get(timeoutMs, TimeUnit.MILLISECONDS))
          ? Health.up().build()
          : Health.down().build();
    } catch (ExecutionException | TimeoutException exception) {
      // Do not log driver messages that might contain connection URLs or credentials.
      LOGGER.warn("Health dependency check failed or timed out.");
      return Health.down().build();
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      return Health.down().build();
    }
  }

  private synchronized Check currentCheck() {
    if (inFlight == null
        || (inFlight.task().isDone()
            && System.nanoTime() - inFlight.completedAt().get() >= cacheNanos)) {
      AtomicLong completedAt = new AtomicLong();
      FutureTask<Boolean> task =
          new FutureTask<>(
              () -> {
                try {
                  return dependenciesAvailable();
                } finally {
                  completedAt.set(System.nanoTime());
                }
              });
      executor.execute(task);
      inFlight = new Check(task, completedAt);
    }
    return inFlight;
  }

  private record Check(FutureTask<Boolean> task, AtomicLong completedAt) {}

  protected abstract boolean dependenciesAvailable()
      throws SQLException, IOException, InterruptedException, ParseException;

  @PreDestroy
  public final void shutdown() {
    executor.shutdownNow();
    releaseResources();
  }

  protected void releaseResources() {
    // Subclasses may release their dependency clients here.
  }
}
