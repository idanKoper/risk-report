package sca.riskreport.service;

import org.springframework.http.ResponseEntity;
import sca.riskreport.model.request.PackageVersionRequest;
import sca.riskreport.model.request.RiskReportRequest;

public interface riskReportService {

    ResponseEntity<String> getRiskReport(RiskReportRequest riskReportRequest);

    ResponseEntity<String> publishPackageVersions(PackageVersionRequest packageVersionRequest);
}
