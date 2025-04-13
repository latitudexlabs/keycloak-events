package io.phasetwo.keycloak.representation;
import java.time.LocalDate;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

@Data
public class UsageRequest {
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate start_date;
    @JsonFormat(pattern = "yyyy-MM-dd")
    private LocalDate end_date;
}
