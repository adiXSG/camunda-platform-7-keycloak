package org.camunda.bpm.extension.keycloak;

/**
 * Thrown in case a query for a unique tenant fails.
 */
public class KeycloakTenantNotFoundException extends Exception {

	/** This class' serial version UID. */
	private static final long serialVersionUID = 4368608195497046998L;

	/**
	 * Creates a new KeycloakTenantNotFoundException.
	 * 
	 * @param message
	 *            the message
	 * @param cause
	 *            the original cause
	 */
	public KeycloakTenantNotFoundException(String message, Throwable cause) {
		super(message, cause);
	}

}
