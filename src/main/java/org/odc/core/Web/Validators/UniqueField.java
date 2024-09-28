package org.odc.core.Web.Validators;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;


@Target({ ElementType.FIELD })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = UniqueLibelleValidator.class)
public @interface UniqueField {
    String message() default "ce nom est deja utilise";

    // Specify the entity class and the field to check
    Class<?> entity();
    String field();

    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
