package org.odc.core.Web.Dtos.Request;

import lombok.Data;

@Data
public class AuthRequest {
    private String email;
    private String password;
}
