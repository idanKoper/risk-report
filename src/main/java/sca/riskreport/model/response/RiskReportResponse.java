package sca.riskreport.model.response;

import lombok.Builder;
import lombok.Data;
import sca.riskreport.model.Vulnerability;

import java.util.List;

@Data
@Builder
public class RiskReportResponse {
    String packageId;
    String packageName;
    String packageManager;
    String version;
    String releaseDate;
    List<Vulnerability> vulnerabilities;
    List<Remediation> remediation;
}
