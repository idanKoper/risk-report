package sca.riskreport.model.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Remediation {
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String fixVersion;
    private String remediationStatus;
}
