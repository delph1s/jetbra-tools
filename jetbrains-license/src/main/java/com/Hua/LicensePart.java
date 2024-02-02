package com.Hua;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author Hua
 * @since 2024-02-01 09:05
 */
public class LicensePart {
    String licenseId;
    String licenseeName;
    String assigneeName;
    String assigneeEmail;
    String licenseRestriction;
    boolean checkConcurrentUse = false;
    List<Product> products;
    String metadate = "0120230914PSAX000005";
    String hash = "TRIAL:-1920204289";
    int gracePeriodDays = 7;
    boolean autoProlongated = true;
    boolean isAutoProlongated = true;


    @Override
    public String toString() {
        return "{" +
                "\"licenseId\":\"" + licenseId + "\"," +
                "\"licenseeName\":\"" + licenseeName + "\"," +
                "\"assigneeName\":\"" + assigneeName + "\"," +
                "\"assigneeEmail\":\"" + assigneeEmail + "\"," +
                "\"licenseRestriction\":\"" + licenseRestriction + "\"," +
                "\"checkConcurrentUse\":" + checkConcurrentUse + "," +
                "\"products\":" + products + "," +
                "\"metadata\":\"" + metadate + "\"," +
                "\"hash\":\"" + hash + "\"," +
                "\"gracePeriodDays\":" + gracePeriodDays + "," +
                "\"autoProlongated\":" + autoProlongated + "," +
                "\"isAutoProlongated\":" + isAutoProlongated +
                "}";
    }

    public LicensePart(String licenseId, String[] codes, String date) {
        this.licenseId = licenseId;
        this.licenseeName = licenseId;
        this.assigneeName = licenseId;
        this.products = Arrays.stream(codes).map(code -> new Product(code, date)).collect(Collectors.toList());
    }

    public class Product {
        String code;
        String fallbackDate;
        String paidUpTo;
        boolean extended = true;

        public Product(String code, String date) {
            this.code = code;
            this.fallbackDate = date;
            this.paidUpTo = date;
        }

        @Override
        public String toString() {
            return "{" +
                    "\"code\":\"" + code + "\"," +
                    "\"fallbackDate\":\"" + fallbackDate + "\"," +
                    "\"paidUpTo\":\"" + paidUpTo +
                    "\"," +
                    "\"extended\":" + extended +
                    "}";
        }
    }
}
