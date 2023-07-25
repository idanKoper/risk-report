package sca.riskreport.model.response;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class PackageVulnerabilitiesResponse {
    List<PackageVulnerabilityResponse> packageVulnerabilitiesResponse;

    public PackageVulnerabilitiesResponse(List<PackageVulnerabilityResponse> packageVulnerabilitiesResponse) {
        this.packageVulnerabilitiesResponse = packageVulnerabilitiesResponse;
    }
}
