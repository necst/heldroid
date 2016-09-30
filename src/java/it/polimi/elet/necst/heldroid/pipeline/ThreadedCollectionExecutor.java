package it.polimi.elet.necst.heldroid.pipeline;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class ThreadedCollectionExecutor<T> {
    public interface ParameterizedRunnable<T> {
        void run(T parameter);
    }

    private ExecutorService executor;
    private int maxThreadCount;
    private int itemsPerThread;

    private TimeUnit timeoutUnit;
    private int timeout;

    public void setTimeout(int delay, TimeUnit unit) {
        if (delay < 0)
            delay = 0;

        this.timeout = delay;
        this.timeoutUnit = unit;
    }

    public ThreadedCollectionExecutor(int maxThreadCount, int itemsPerThread) {
        this.maxThreadCount = maxThreadCount;
        this.itemsPerThread = itemsPerThread;
        this.executor = Executors.newFixedThreadPool(maxThreadCount);

        timeout = 5;
        timeoutUnit = TimeUnit.SECONDS;
    }

    /**
     * Executs the given task on each item of the given collection. Up to itemsPerThread tasks are executed in the same
     * thread. If more than itemsPerThread items are present, each chunk is executed in a new thread, up to a maximum
     * of maxThreadCount. The method returns when all items have been executed a task on.
     * @param collection Generic collection of items.
     * @param task Generic task, represented by a Runnable-like interface (accepting 1 parameter for run).
     */
    public void execute(Collection<T> collection, final ParameterizedRunnable<T> task) {
        List<T> tempList = new ArrayList<T>(itemsPerThread);
        int i = 0;

        for (T item : collection) {
            if (i++ < itemsPerThread)
                tempList.add(item);
            else {
                final List<T> listReference = tempList;

                executor.execute(new Runnable() {
                    @Override
                    public void run() {
                        for (T itemReference : listReference) {
                            if (Thread.currentThread().isInterrupted())
                                return;

                            task.run(itemReference);
                        }
                    }
                });

                tempList = new ArrayList<T>(itemsPerThread);
                tempList.add(item);
                i = 1;
            }
        }

        if (tempList.size() > 0) {
            final List<T> listReference = tempList;

            executor.execute(new Runnable() {
                @Override
                public void run() {
                    for (T itemReference : listReference) {
                        if (Thread.currentThread().isInterrupted())
                            return;

                        task.run(itemReference);
                    }
                }
            });
        }

        try {
            executor.shutdown();

            // enforces termination strictly before actual timeout
            // usually aborting threads take around 0.001 seconds more than the timeout
            long millis = (long)(timeoutUnit.toMillis(timeout) * 0.95);

            if (executor.awaitTermination(millis, TimeUnit.MILLISECONDS) == false)
                executor.shutdownNow(); // forces shutdown
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
