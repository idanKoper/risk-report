package sca.riskreport.model.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RiskReportRequest extends Request {

    @NotBlank(message = "package version is mandatory")
    private String packageVersion;

    public RiskReportRequest(String packageVersion,
                             @NotNull(message = "package manager is mandatory") String packageManager,
                             @NotNull(message = "package name is mandatory") String packageName) {
        super(packageManager, packageName);
        this.packageVersion = packageVersion;
    }
}
