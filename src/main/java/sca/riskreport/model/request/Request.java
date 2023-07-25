package sca.riskreport.model.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Request {
    @NotBlank(message = "package manager is mandatory")
    private String packageManager;

    @NotBlank(message = "package name is mandatory")
    private String packageName;

    public Request(String packageManager, String packageName) {
        this.packageManager = packageManager;
        this.packageName = packageName;
    }
}
