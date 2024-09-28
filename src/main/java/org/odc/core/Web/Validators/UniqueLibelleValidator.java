package org.odc.core.Web.Validators;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class UniqueLibelleValidator implements ConstraintValidator<UniqueField,String> {
    @PersistenceContext
    private EntityManager entityManager; // Inject EntityManager to dynamically query entities

    private Class<?> entityClass;
    private String fieldName;

    @Override
    public void initialize(UniqueField constraintAnnotation) {
        this.entityClass = constraintAnnotation.entity();
        this.fieldName = constraintAnnotation.field();
    }


    @Override
    public boolean isValid(String fieldValue, ConstraintValidatorContext context) {
        if (fieldValue == null) {
            return true; // consider null values as valid
        }

        String queryStr = String.format("SELECT COUNT(e) FROM %s e WHERE e.%s = :fieldValue",
                entityClass.getSimpleName(), fieldName);

        Long count = entityManager.createQuery(queryStr, Long.class)
                .setParameter("fieldValue", fieldValue)
                .getSingleResult();

        return count == 0;
    }
}
