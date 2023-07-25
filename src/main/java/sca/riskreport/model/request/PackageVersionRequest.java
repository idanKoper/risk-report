package sca.riskreport.model.request;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class PackageVersionRequest extends Request {

    @NotEmpty(message = "package version is mandatory")
    private List<String> packageVersion;

    PackageVersionRequest(@NotNull(message = "package manager is mandatory") String packageManager,
                          @NotNull(message = "package name is mandatory") String packageName) {
        super(packageManager, packageName);
    }
}
