package com.securebank.lab.common;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Small helpers shared by the lab controllers.
 */
public final class LabResponses {

    private LabResponses() {
    }

    /**
     * Builds an ordered map for JSON responses.
     */
    public static Map<String, Object> map(Object... keyValues) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i + 1 < keyValues.length; i += 2) {
            result.put(String.valueOf(keyValues[i]), keyValues[i + 1]);
        }
        return result;
    }

    /**
     * Renders an account for API output.
     */
    public static Map<String, Object> renderAccount(com.securebank.core.account.Account account) {
        return map(
                "id", account.getId(),
                "account_number", account.getAccountNumber(),
                "sort_code", account.getSortCode(),
                "balance", account.getBalance(),
                "currency", account.getCurrency());
    }

    /**
     * Renders a transfer for API output.
     */
    public static Map<String, Object> renderTransfer(com.securebank.core.transfer.Transfer transfer) {
        return map(
                "id", transfer.getId(),
                "from_account_id", transfer.getFromAccountId(),
                "to_account_id", transfer.getToAccountId(),
                "amount", transfer.getAmount(),
                "note", transfer.getNote(),
                "remark", transfer.getRemark(),
                "created_at", transfer.getCreatedAt());
    }
}
