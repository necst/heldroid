package it.polimi.elet.necst.heldroid.goodware.markets;

import com.gc.android.market.api.MarketSession;
import com.gc.android.market.api.model.Market;
import com.gc.android.market.api.model.Market.*;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class GooglePlayStore {
    // TODO make this a property :-) but at the end of the day we don't care about leaking a dummy account
    private static final String GOOGLE_USERNAME = "goodware.bot@gmail.com";
    private static final String GOOGLE_PASSWORD = "mucca-fritta-007";
    private static final String FAILURE_FILE_NAME = "google-play-failed-queries.txt";

    private static BufferedWriter failureWriter;

    private MarketSession session;
    private boolean extendedInfo;
    private int defaultEntriesCount;

    static {
        try {
            failureWriter = new BufferedWriter(new FileWriter(new File(FAILURE_FILE_NAME), true));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public GooglePlayStore() {
        this.extendedInfo = true;
        this.defaultEntriesCount = 10;
    }

    private void login() {
        if (session != null)
            return;

        session = new MarketSession();
        session.login(GOOGLE_USERNAME, GOOGLE_PASSWORD);
    }

    public Collection<App> search(String query, int startIndex, int entriesCount) {
        this.login();

        List<App> results = new ArrayList<App>();

        for (int i = startIndex; i < entriesCount; i += 10) {
            Market.AppsRequest appsRequest = Market.AppsRequest.newBuilder()
                    .setQuery(query)
                    .setStartIndex(i).setEntriesCount(10)
                    .setWithExtendedInfo(extendedInfo)
                    .build();

            List<App> tmp = getAppsFromRequest(appsRequest);
            results.addAll(tmp);

            if (tmp.size() < 10)
                break;
        }

        return results;
    }

    public Collection<App> searchByCategory(String category, int startIndex, int entriesCount) {
        this.login();

        List<App> results = new ArrayList<App>();

        for (int i = startIndex; i < entriesCount; i += 10) {
            Market.AppsRequest appsRequest = Market.AppsRequest.newBuilder()
                    .setStartIndex(i).setEntriesCount(10)
                    .setCategoryId(category)
                    .setOrderType(AppsRequest.OrderType.POPULAR)
                    .setWithExtendedInfo(extendedInfo)
                    .build();

            List<App> tmp = getAppsFromRequest(appsRequest);
            results.addAll(tmp);

            if (tmp.size() < 10)
                break;
        }

        return results;
    }

    private List<App> getAppsFromRequest(AppsRequest appsRequest) {
        List<App> results = new ArrayList<App>();

        try {
            List<Object> responses = session.queryApp(appsRequest);

            for(int i = 0; i < responses.size(); i++) {
                AppsResponse response = (AppsResponse) responses.get(i);

                if (response.getAppCount() == 0)
                    continue;

                results.addAll(response.getAppList());
            }
        } catch (RuntimeException rex) {
            // Too many requests
            synchronized (failureWriter) {
                if (failureWriter != null) {
                    try {
                        failureWriter.write(appsRequest.getQuery());
                        failureWriter.newLine();
                        failureWriter.flush();
                    } catch (IOException e) { }
                }
            }
        }

        return results;
    }

    public Collection<App> search(String query) {
        return search(query, 0, defaultEntriesCount);
    }

    public Collection<App> searchByCategory(String category) {
        return searchByCategory(category, 0, defaultEntriesCount);
    }

    public App findApplication(String appName) {
        Collection<App> foundApps = search(appName, 0, 5);

        if (foundApps.size() == 0)
            return null;

        Iterator<App> iterator = foundApps.iterator();
        return iterator.next();
    }

    public App findPackage(String packageName) {
        return findApplication("pname:" + packageName);
    }

    public static final String[] APP_CATEGORIES = {
            "COMICS",
            "FINANCE",
            "LIFESTYLE",
            "PRODUCTIVITY",
            "SHOPPING",
            "SPORTS",
            "TOOLS",
            "TRAVEL_AND_LOCAL",
            "BUSINESS",
            "EDUCATION",
            "NEWS_AND_MAGAZINES",
            "MEDIA_AND_VIDEO",
            "MUSIC_AND_AUDIO",
            "HEALTH_AND_FITNESS",
            "MEDICAL",
            "PERSONALIZATION",
            "BOOKS_AND_REFERENCE",
            "PHOTOGRAPHY",
            "WEATHER",
            "COMMUNICATION",
            "SOCIAL"
    };

    public boolean hasExtendedInfo() {
        return extendedInfo;
    }

    public void setExtendedInfo(boolean extendedInfo) {
        this.extendedInfo = extendedInfo;
    }

    public int getDefaultEntriesCount() {
        return defaultEntriesCount;
    }

    public void setDefaultEntriesCount(int defaultEntriesCount) {
        this.defaultEntriesCount = defaultEntriesCount;
    }
}
