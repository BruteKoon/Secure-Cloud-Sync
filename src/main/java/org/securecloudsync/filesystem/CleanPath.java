package org.securecloudsync.filesystem;

import com.sun.istack.internal.NotNull;

/**
 * 경로 우회를 막기 위한 클레스
 */
public class CleanPath {
    @NotNull
    public static String cleanString(String aString) {

        if (aString == null) return "false";

        return checkString(aString);
    }

    @NotNull
    public static String checkString(@NotNull String aChar) {
        return aChar.replace("..\\", "").
                replace("../", "").
                replace("\\.\\.", "").
                replace("\\\\\\\\", "").
                replace("%", "");
    }
}