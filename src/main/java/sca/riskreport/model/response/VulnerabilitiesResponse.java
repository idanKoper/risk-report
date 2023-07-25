package sca.riskreport.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class VulnerabilitiesResponse {
    private String cve;
    private String description;
    private String cwe;
    private String published;
    private String severity;
}
