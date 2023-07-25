package sca.riskreport.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import sca.riskreport.model.Vulnerability;
import sca.riskreport.model.request.PackageVersionRequest;
import sca.riskreport.model.request.RiskReportRequest;
import sca.riskreport.model.response.*;
import sca.riskreport.utils.RestUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

@Service
public class riskReportServiceImpl implements riskReportService {
    private static final String SLASH = "/";
    private static final String VERSIONS = "versions/";
    private static final String USER_AGENT_HEADER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36";
    private static final String NO_REMEDIATION_EXISTS_STATUS = "NoRemediationExists";
    private static final String REMEDIATION_STATUS = "Remediated";

    //knownVersionPackages {key: {packageName, packageManager}, value: {List<String> versions}}
    HashMap<List<String>, List<String>> knownVersionPackages = new HashMap<>();

    private final ObjectMapper mapper = new ObjectMapper();
    private final RestTemplate restTemplate = new RestTemplate();

    @Override
    public ResponseEntity<String> getRiskReport(RiskReportRequest riskReportRequest) {
        List<String> packagesVersions = knownVersionPackages.get(Arrays.asList(riskReportRequest.getPackageName(),
                riskReportRequest.getPackageManager()));
        if (packagesVersions == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "The Package name: " + riskReportRequest.getPackageName() +
                    " and package versions: " + riskReportRequest.getPackageVersion() + " not found");
        } else {
            PackageInformationResponse packageInformationResponse = getPackageInformation(riskReportRequest);
            PackageVulnerabilitiesResponse packageVulnerabilities = getPackageVulnerabilities(riskReportRequest);
            List<Remediation> remediations = getRemediationVersion(riskReportRequest);
            RiskReportResponse riskReportResponse = generateRiskReportResponse(riskReportRequest, packageInformationResponse,
                    packageVulnerabilities, remediations);
            try {
                return new ResponseEntity<>(mapper.writeValueAsString(riskReportResponse), HttpStatus.OK);
            } catch (JsonProcessingException e) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Cannot convert risk report object to Json");
            }
        }
    }

    @Override
    public ResponseEntity<String> publishPackageVersions(PackageVersionRequest packageVersionRequest) {
        List<String> knownPackageVersions = knownVersionPackages.get(Arrays.asList(packageVersionRequest.getPackageName(),
                packageVersionRequest.getPackageManager()));
        if (knownPackageVersions == null) {
            addPackageManagerVersions(packageVersionRequest);
        } else {
            knownPackageVersions.addAll(packageVersionRequest.getPackageVersion());
        }

        return ResponseEntity.ok().build();
    }

    private void addPackageManagerVersions(PackageVersionRequest packageVersionRequest) {
        knownVersionPackages.put(Arrays.asList(packageVersionRequest.getPackageName(), packageVersionRequest.getPackageManager()),
                new ArrayList<>(packageVersionRequest.getPackageVersion()));
    }

    private RiskReportResponse generateRiskReportResponse(RiskReportRequest riskReportRequest,
                                                          PackageInformationResponse packageInformationResponse,
                                                          PackageVulnerabilitiesResponse packageVulnerabilitiesResponse,
                                                          List<Remediation> remediation) {
        return RiskReportResponse.builder()
                .packageId(packageInformationResponse.getPackageId())
                .packageName(riskReportRequest.getPackageName())
                .packageManager(riskReportRequest.getPackageName())
                .version(riskReportRequest.getPackageVersion())
                .releaseDate(packageInformationResponse.getReleaseDate())
                .vulnerabilities(convertVulnerabilitiesResponseToRiskResponse(packageVulnerabilitiesResponse))
                .remediation(remediation)
                .build();
    }

    private List<Vulnerability> convertVulnerabilitiesResponseToRiskResponse(PackageVulnerabilitiesResponse packageVulnerabilitiesResponse) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        for (PackageVulnerabilityResponse packageVulnerabilityResponse : packageVulnerabilitiesResponse.getPackageVulnerabilitiesResponse()) {
            List<Vulnerability> vulnerabilitiesRiskResponse = new ArrayList<>();
            for (VulnerabilitiesResponse vulnerabilitiesResponse : packageVulnerabilityResponse.getVulnerabilities()) {
                Vulnerability vulnerability = generateVulnerability(vulnerabilitiesResponse);
                vulnerabilitiesRiskResponse.add(vulnerability);
            }
            vulnerabilities.addAll(vulnerabilitiesRiskResponse);
        }
        return vulnerabilities;
    }

    private static Vulnerability generateVulnerability(VulnerabilitiesResponse vulnerabilitiesResponse) {
        return Vulnerability.builder()
                .cve(vulnerabilitiesResponse.getCve())
                .description(vulnerabilitiesResponse.getDescription())
                .cwe(vulnerabilitiesResponse.getCwe())
                .published(vulnerabilitiesResponse.getPublished())
                .severity(vulnerabilitiesResponse.getSeverity())
                .build();
    }

    private List<Remediation> getRemediationVersion(RiskReportRequest riskReportRequest) {
        List<Remediation> remediations = new ArrayList<>();
        List<String> packagesVersions = knownVersionPackages.get(Arrays.asList(riskReportRequest.getPackageName(),
                riskReportRequest.getPackageManager()));
        ComparableVersion riskReportPackageVersion = new ComparableVersion(riskReportRequest.getPackageVersion());
        for (String packageVersion : packagesVersions) {
            ComparableVersion packageVersionAsComparable = new ComparableVersion(packageVersion);
            if (packageVersionAsComparable.compareTo(riskReportPackageVersion) > 0) {
                isPackageVersionIsFixed(riskReportRequest, remediations, packageVersion);
            }
        }

        handleNoRemediationExists(remediations);
        return remediations;
    }

    private static void handleNoRemediationExists(List<Remediation> remediations) {
        if (remediations.isEmpty()) {
            remediations.add(Remediation.builder().remediationStatus(NO_REMEDIATION_EXISTS_STATUS).build());
        }
    }

    private void isPackageVersionIsFixed(RiskReportRequest riskReportRequest, List<Remediation> remediations, String packageVersion) {
        RiskReportRequest requestForGetVulnerabilities = new RiskReportRequest(packageVersion,
                riskReportRequest.getPackageManager(), riskReportRequest.getPackageName());
        PackageVulnerabilitiesResponse packageVulnerabilities = getPackageVulnerabilities(requestForGetVulnerabilities);
        for (PackageVulnerabilityResponse packageVulnerabilityResponse : packageVulnerabilities.getPackageVulnerabilitiesResponse()) {
            if (packageVulnerabilityResponse.getVulnerabilities().isEmpty()) {
                remediations.add(Remediation.builder().remediationStatus(REMEDIATION_STATUS).fixVersion(packageVersion).build());
            }
        }
    }

    private PackageInformationResponse getPackageInformation(RiskReportRequest riskReportRequest) {
        String url = RestUtils.PACKAGE_INFORMATION_BASE_URL + riskReportRequest.getPackageManager() + SLASH +
                riskReportRequest.getPackageName() + SLASH + VERSIONS + riskReportRequest.getPackageVersion();
        return restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(getHeaders()), PackageInformationResponse.class).getBody();
    }

    private PackageVulnerabilitiesResponse getPackageVulnerabilities(RiskReportRequest riskReportRequest) {
        String url = RestUtils.VULNERABILITIES_INFORMATION_BASE_URL;
        HttpEntity httpEntity = new HttpEntity(getBody(riskReportRequest), getHeaders());
        PackageVulnerabilityResponse[] packageVulnerabilitiesResponse = restTemplate.exchange(url, HttpMethod.POST, httpEntity,
                PackageVulnerabilityResponse[].class).getBody();
        if (packageVulnerabilitiesResponse != null) {
            return new PackageVulnerabilitiesResponse(List.of(packageVulnerabilitiesResponse));
        } else {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error occurred with vulnerabilities information API");
        }
    }

    private List<Object> getBody(RiskReportRequest riskReportRequest) {
        HashMap<String, String> body = new HashMap<>();
        body.put("packageName", riskReportRequest.getPackageName());
        body.put("packageManager", riskReportRequest.getPackageManager());
        body.put("version", riskReportRequest.getPackageVersion());

        return List.of(body);
    }

    private HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.add("User-Agent", USER_AGENT_HEADER);
        return headers;
    }
}
