package sca.riskreport.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class PackageInformationResponse {
    private String packageId;
    private String releaseDate;
}
