package org.keycloak.protocol.oidc.ida.mappers.extractor;

import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

class ExtractorConstants {
    public static final String JQ_DATE_FUNCTIONS = 
        "def convertTime(time):time|(try(.|gmtime)//try(.|strptime(\"%Y-%m-%d\"))//try(.|strptime(\"%Y-%m-%dT%H:%MZ\"))//try(.|strptime(\"%Y-%m-%dT%HZ\"))//try(.|strptime(\"%Y-%m-%dT%H:%M:%SZ\")))|mktime;def isRecentEnough(arg):arg as [$time, $max_age]|(now-convertTime($time))<convertTime($max_age);";

    public static final String KEY_FILTER_VALUE = "value";
    public static final String KEY_FILTER_VALUES = "values";
    public static final String KEY_FILTER_ESSENTIAL = "essential";
    public static final String KEY_FILTER_MAX_AGE = "max_age";
    public static final String KEY_FILTER_PURPOSE = "purpose";

    public static final List<String> KEY_FILTER_LIST = new ArrayList<String>();
    static {
        KEY_FILTER_LIST.add(KEY_FILTER_VALUE);
        KEY_FILTER_LIST.add(KEY_FILTER_VALUES);
        KEY_FILTER_LIST.add(KEY_FILTER_ESSENTIAL);
        KEY_FILTER_LIST.add(KEY_FILTER_MAX_AGE);
        KEY_FILTER_LIST.add(KEY_FILTER_PURPOSE);
    }

    public static final String KEY_ARRAY_MAX_AGE = "assurance_details";

    public static final String KEY_VERIFICATION = "verification";

    public static final String KEY_CLAIMS = "claims";

    public static final List<String> arrayKeys = new ArrayList<>();
    static {
        arrayKeys.add("check_details");
        arrayKeys.add("attachments");
        arrayKeys.add("assurance_details");
        arrayKeys.add("evidence");
        arrayKeys.add("evidence_ref");
    }

    public static final List<DateTimeFormatter> DATETIME_FORMATTERS = Arrays.asList(
            // Offset corresponds to ±hh,±hh:mm format
            DateTimeFormatter.ISO_OFFSET_DATE_TIME,
            // Offset corresponds to ±hh,±hhmm format
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssX"),
            // Offset corresponds to ±hh,±hhmm format
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mmX"));

    public static final String WARN_MESSAGE_CANNOT_PARSE_DATETIME = "Can't parse dateTime(%s).";
    public static final String WARN_MESSAGE_REQUESTED_CLAIM_IS_NOT_IN_VERIFIED_CLAIMS = "Ignore if the requested claim(%s) is not in Verified Claims";
}