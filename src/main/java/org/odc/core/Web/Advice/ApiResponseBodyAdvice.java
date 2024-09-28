package org.odc.core.Web.Advice;

import jakarta.servlet.http.HttpServletRequest;
import org.odc.core.Web.Dtos.Response.ApiResponse;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@ControllerAdvice
public class ApiResponseBodyAdvice implements ResponseBodyAdvice<Object> {

    private static final String[] EXCLUDED_PATHS = {
            "/swagger-ui",
            "/v3/api-docs",
            "/v2/api-docs",
            "/swagger-ui.html",
            "/swagger-resources",
            "/error", // Exclude error path
            "/actuator",
            "/api-docs",
            "/api/v1/auth/"
    };

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        String path = getRequestPath();
        if (path != null) {
            for (String excludedPath : EXCLUDED_PATHS) {
                if (path.startsWith(excludedPath)) {
                    return false; // Do not apply to excluded paths
                }
            }
        }
        return true; // Apply to other paths
    }

    @Override
    public Object beforeBodyWrite(
            Object body,
            MethodParameter returnType,
            MediaType selectedContentType,
            Class<? extends HttpMessageConverter<?>> selectedConverterType,
            org.springframework.http.server.ServerHttpRequest request,
            org.springframework.http.server.ServerHttpResponse response) {

        if (body instanceof ApiResponse) {
            return body;
        }

        if (body == null) {
            return new ApiResponse<>(null, "No data found");
        }

        return new ApiResponse<>(body, "Success");
    }

    private String getRequestPath() {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs != null) {
            HttpServletRequest request = attrs.getRequest();
            return request.getRequestURI();
        }
        return null;
    }
}
