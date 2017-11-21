package uk.gov.ida.verifyserviceprovider.utils;

import org.apache.commons.lang3.StringUtils;

import java.util.List;

import static java.lang.System.lineSeparator;
import static java.util.stream.Collectors.joining;

public class StringTableFormatter {

    private static final String TABLE_SIDE_BORDER = "|";
    private static final String TABLE_TITLE_SEPARATOR = "-";
    private static final String TABLE_LINE_BORDER = "=";

    public static String format(int tableWidth, String title, List<String> rows) {
        return formatTitle(tableWidth, title) +
            formatBody(rows) +
            formatBottomBorder(tableWidth);
    }

    private static String formatTitle(int tableWidth, String title) {
        String tableTopBorder = StringUtils.repeat(TABLE_LINE_BORDER, tableWidth) + lineSeparator();
        String tableTitleRow = TABLE_SIDE_BORDER + " " + title + lineSeparator();
        String tableTitleBottomBorder = StringUtils.repeat(TABLE_TITLE_SEPARATOR, tableWidth) + lineSeparator();

        return lineSeparator() +
            tableTopBorder +
            tableTitleRow +
            tableTitleBottomBorder;
    }

    private static String formatBody(List<String> rowsData) {
        String rowsLines = rowsData.stream()
            .map(item -> TABLE_SIDE_BORDER + " " + item)
            .collect(joining(lineSeparator()));

        return rowsLines + lineSeparator();
    }

    private static String formatBottomBorder(int tableWidth) {
        return StringUtils.repeat(TABLE_LINE_BORDER, tableWidth) + lineSeparator();
    }
}
