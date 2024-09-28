package org.odc.core.Web.Dtos.Response;

import lombok.Data;

@Data
public class ApiResponse<T> {
    private boolean status;
    private T data;
    private String message;

    public ApiResponse(T data, String message) {
        this.data = data;
        this.status = data != null;
        this.message = message;
    }
}
