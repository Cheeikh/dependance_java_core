package org.odc.core.Exceptions;

public class ArgumentInsuffisantException extends RuntimeException {
    public ArgumentInsuffisantException(String message) {
        super(message);
    }

  public ArgumentInsuffisantException(String message, Throwable cause) {
    super(message, cause);
  }
}
