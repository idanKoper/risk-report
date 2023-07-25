package sca.riskreport.controller;

import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import sca.riskreport.model.request.PackageVersionRequest;
import sca.riskreport.model.request.RiskReportRequest;
import sca.riskreport.service.riskReportService;

@RestController
@RequestMapping("/checkmarx/vulnerabilities/")
public class SCAController {

    private final riskReportService riskReportService;

    public SCAController(riskReportService riskReportService) {
        this.riskReportService = riskReportService;
    }

    @RequestMapping(path = "/getRiskReport", method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> getRiskReport(@Valid @RequestParam String packageManager,
                                                @Valid @RequestParam String packageName,
                                                @Valid @RequestParam String packageVersion) {
        return riskReportService.getRiskReport(new RiskReportRequest(packageVersion, packageManager, packageName));
    }

    @RequestMapping(path = "/publish", method = RequestMethod.POST, consumes = "application/json")
    public ResponseEntity<String> publishPackageVersions(@Valid @RequestBody PackageVersionRequest packageVersionRequest) {
        return riskReportService.publishPackageVersions(packageVersionRequest);
    }
}
