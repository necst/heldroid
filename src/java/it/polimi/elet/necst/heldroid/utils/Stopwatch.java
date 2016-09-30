package it.polimi.elet.necst.heldroid.utils;

public class Stopwatch {
    public static double time(Runnable runnable) {
        Long startTime, endTime;

        startTime = System.currentTimeMillis();
        runnable.run();
        endTime = System.currentTimeMillis();

        return (double)(endTime - startTime) / 1000.0;
    }
}
