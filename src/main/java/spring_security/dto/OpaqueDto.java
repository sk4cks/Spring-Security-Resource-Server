package spring_security.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.Authentication;

@Data
@Builder
public class OpaqueDto {

    private boolean active;
    private Authentication authentication;
    private Object principal;
}
