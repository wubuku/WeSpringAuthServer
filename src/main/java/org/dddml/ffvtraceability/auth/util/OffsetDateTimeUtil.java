package org.dddml.ffvtraceability.auth.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;

public class OffsetDateTimeUtil {
    private static final Logger logger = LoggerFactory.getLogger(OffsetDateTimeUtil.class);

    public static OffsetDateTime toOffsetDateTime(Object dbValue) {
        OffsetDateTime passwordLastChanged = null;

        if (dbValue != null) {
            // 处理所有可能的时间类型
            if (dbValue instanceof OffsetDateTime) {
                passwordLastChanged = (OffsetDateTime) dbValue;
            } else if (dbValue instanceof Timestamp ts) {
                passwordLastChanged = ts.toInstant()
                        .atOffset(ZoneOffset.systemDefault().getRules().getOffset(Instant.now()));
            } else if (dbValue instanceof LocalDateTime ldt) {
                passwordLastChanged = ldt.atOffset(ZoneOffset.systemDefault().getRules().getOffset(Instant.now()));
            } else if (dbValue instanceof Date date) {
                passwordLastChanged = date.toInstant()
                        .atOffset(ZoneOffset.systemDefault().getRules().getOffset(Instant.now()));
            } else {
//                logger.warn("Unexpected datetime type: {} for value: {}",
//                        dbValue.getClass().getName(), dbValue);
                throw new IllegalArgumentException("Unsupported datetime type: " + dbValue.getClass().getName());
            }
        }
        logger.debug("Password last changed type: {}, value: {}",
                dbValue != null ? dbValue.getClass().getName() : "null",
                passwordLastChanged);
        return passwordLastChanged;
    }
}
