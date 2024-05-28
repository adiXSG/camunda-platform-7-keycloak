package org.camunda.bpm.extension.keycloak;

import static org.camunda.bpm.extension.keycloak.json.JsonUtil.createCustomAttributePredicate;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.findFirst;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.getJsonArray;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.getJsonObjectAtIndex;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.getJsonString;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.parseAsJsonObject;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.parseAsJsonObjectAndGetMemberAsString;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;

import org.camunda.bpm.engine.authorization.Permission;
import org.camunda.bpm.engine.authorization.Resource;
import org.camunda.bpm.engine.impl.identity.IdentityProviderException;
import org.camunda.bpm.engine.impl.persistence.entity.UserEntity;
import org.camunda.bpm.extension.keycloak.json.JsonException;
import org.camunda.bpm.extension.keycloak.rest.KeycloakRestTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * Base class for services implementing user / group queries against Keycloak.
 * Provides general helper methods.
 */
public abstract class KeycloakServiceBase {

	public static final String GROUP_PATH_DELIMITER = " ¦ ";
	public static final int GROUP_PATH_DELIMITER_LENGTH = GROUP_PATH_DELIMITER.length();

	protected KeycloakConfiguration keycloakConfiguration;
	protected KeycloakRestTemplate restTemplate;
	protected KeycloakContextProvider keycloakContextProvider;

	/**
	 * Default constructor.
	 * 
	 * @param keycloakConfiguration the Keycloak configuration
	 * @param restTemplate REST template
	 * @param keycloakContextProvider Keycloak context provider
	 */
	public KeycloakServiceBase(KeycloakConfiguration keycloakConfiguration,
			KeycloakRestTemplate restTemplate, KeycloakContextProvider keycloakContextProvider) {
		this.keycloakConfiguration = keycloakConfiguration;
		this.restTemplate = restTemplate;
		this.keycloakContextProvider = keycloakContextProvider;
	}

	//-------------------------------------------------------------------------
	// User and Group ID Mappings dependent on configuration settings
	//-------------------------------------------------------------------------

	/**
	 * Gets the Keycloak internal ID of an user.
	 * @param userId the userId as sent by the client
	 * @return the Keycloak internal ID
	 * @throws KeycloakUserNotFoundException in case the user cannot be found
	 * @throws RestClientException in case of technical errors
	 */
	protected String getKeycloakUserID(String userId) throws KeycloakUserNotFoundException, RestClientException {
		String userSearch;
		if (keycloakConfiguration.isUseEmailAsCamundaUserId()) {
			userSearch= "/users?email=";
		} else if (keycloakConfiguration.isUseCustomAttributeAsCamundaUserId()) {
			userSearch = "/users?q=" + keycloakConfiguration.getUserIdCustomAttribute() + ":";
		} else if (keycloakConfiguration.isUseUsernameAsCamundaUserId()) {
			userSearch="/users?username=";
		} else {
			return userId;
		}
		
		try {
			URI uri = UriComponentsBuilder
					.fromUriString(keycloakConfiguration.getKeycloakAdminUrl() + userSearch + URLEncoder.encode(userId, StandardCharsets.UTF_8.name()))
					.build(true)
					.toUri();
			ResponseEntity<String> response = restTemplate.exchange(
					uri,
					HttpMethod.GET,
					keycloakContextProvider.createApiRequestEntity(),
					String.class);
			return getJsonString(findUser(response, userId).orElseThrow(), "id");

		} catch (HttpClientErrorException.NotFound | JsonException | NoSuchElementException je) {
			throw new KeycloakUserNotFoundException(userId + 
					(keycloakConfiguration.isUseEmailAsCamundaUserId() 
							? " not found - email unknown"
							: keycloakConfiguration.isUseCustomAttributeAsCamundaUserId() ? "custom attribute value unknown"
					: " not found - username unknown"), je);
		}
		catch (UnsupportedEncodingException e) {
			throw new KeycloakUserNotFoundException(userId + " not encodable", e);
		}
	}
	
	/**
	 * Gets the Keycloak internal ID of a group.
	 * @param groupId the userId as sent by the client
	 * @return the Keycloak internal ID
	 * @throws KeycloakGroupNotFoundException in case the group cannot be found
	 * @throws RestClientException in case of technical errors
	 */
	protected String getKeycloakGroupIdOfTenant(String groupId) throws KeycloakGroupNotFoundException, RestClientException {
		String groupSearch;
		if (keycloakConfiguration.isUseGroupPathAsCamundaGroupId()) {
			String keycloakName = prefixKeycloakGroupPath(groupId);
			groupSearch = "/group-by-path/" + keycloakName.replace(GROUP_PATH_DELIMITER, "/");
		} else {
			return groupId;
		}
		
		try {
			ResponseEntity<String> response = restTemplate.exchange(
					keycloakConfiguration.getKeycloakAdminUrl() + groupSearch, HttpMethod.GET, String.class);
			return parseAsJsonObjectAndGetMemberAsString(response.getBody(), "id");
		} catch (HttpClientErrorException.NotFound | JsonException je) {
			throw new KeycloakGroupNotFoundException(groupId + " not found - path unknown", je);
		}
	}
	
	/**
	 * Gets the Keycloak internal ID of a group.
	 * 
	 * @param groupId
	 *            the userId as sent by the client
	 * @return the Keycloak internal ID
	 * @throws KeycloakGroupNotFoundException
	 *             in case the group cannot be found
	 * @throws RestClientException
	 *             in case of technical errors
	 */
	protected String getKeycloakGroupId(String groupId) throws KeycloakGroupNotFoundException, RestClientException {
		String groupSearch;
		if (keycloakConfiguration.isUseGroupPathAsCamundaGroupId()) {
			groupSearch = "/group-by-path/" + groupId.replace(GROUP_PATH_DELIMITER, "/");
		} else {
			return groupId;
		}

		try {
			ResponseEntity<String> response = restTemplate.exchange(keycloakConfiguration.getKeycloakAdminUrl() + groupSearch,
					HttpMethod.GET, String.class);
			return parseAsJsonObjectAndGetMemberAsString(response.getBody(), "id");
		} catch (HttpClientErrorException.NotFound | JsonException je) {
			throw new KeycloakGroupNotFoundException(groupId + " not found - path unknown", je);
		}
	}

	protected String prefixKeycloakGroupPath(String groupId) {
		if (keycloakConfiguration.isUseGroupPathAsCamundaGroupId()) {
			String tenantGroupName = keycloakConfiguration.getTenantRootGroupName();
			return getContextRoot()
					+ (StringUtils.hasLength(tenantGroupName) && !tenantGroupName.equals(groupId) && !isAdminGroupOrSubgroup(groupId)
							? tenantGroupName + "/" + groupId
							: groupId);
		} else {
			return groupId;
		}
	}

	private boolean isAdminGroupOrSubgroup(String pathGroupId) {
		String adminGroupName = keycloakConfiguration.administratorGroupName;
		return adminGroupName.equals(pathGroupId) || StringUtils.startsWithIgnoreCase(pathGroupId, adminGroupName + GROUP_PATH_DELIMITER);
	}

	/**
	 * Gets the Keycloak internal ID of a tenant group.
	 * 
	 * @param tenantId
	 *            the tenantId as sent by the client
	 * @return the Keycloak internal ID
	 * @throws KeycloakTenantNotFoundException
	 *             in case the tenant group cannot be found
	 * @throws RestClientException
	 *             in case of technical errors
	 */
	protected String getKeycloakTenantID(String tenantId) throws KeycloakTenantNotFoundException, RestClientException {
		String groupSearch;
		if (keycloakConfiguration.isUseGroupNameAsTenantId()) {
			String tenantGroupName = keycloakConfiguration.getTenantRootGroupName();
			String keycloakName = getContextRoot() + (StringUtils.hasLength(tenantGroupName) ? tenantGroupName + "/" + tenantId : tenantId);
			groupSearch = "/group-by-path/" + keycloakName;
		} else {
			return tenantId;
		}

		try {
			ResponseEntity<String> response = restTemplate.exchange(keycloakConfiguration.getKeycloakAdminUrl() + groupSearch,
					HttpMethod.GET, String.class);
			return parseAsJsonObjectAndGetMemberAsString(response.getBody(), "id");
		} catch (HttpClientErrorException.NotFound | JsonException je) {
			throw new KeycloakTenantNotFoundException(tenantId + " not found - path unknown", je);
		}
	}

	//-------------------------------------------------------------------------
	// General helper methods
	//-------------------------------------------------------------------------

	/**
	 * Return the maximum result size of Keycloak queries as String.
	 * @return maximum results for Keycloak search requests
	 */
	protected String getMaxQueryResultSize() {
		return Integer.toString(keycloakConfiguration.getMaxResultSize());
	}
	
	/**
	 * Truncates a list to a given maximum size.
	 * @param <T> element type of list
	 * @param list the original list
	 * @param maxSize the maximum size
	 * @return the truncated list
	 */
	protected <T> List<T> truncate(List<T> list, int maxSize) {
		if (list == null) return list;
		int actualSize = list.size();
		if (actualSize <=  maxSize) return list;
		return list.subList(0, maxSize);
	}
	
	/**
	 * Adds a single argument to search filter
	 * @param filter the current filter
	 * @param name the name of the attribute
	 * @param value the value to search
	 */
	protected void addArgument(StringBuilder filter, String name, String value) {
		if (filter.length() > 0) {
			filter.append("&");
		}
		filter.append(name).append('=').append(value);
	}

	/**
	 * Checks whether a filter applies.
	 * @param queryParameter the queryParameter
	 * @param attribute the corresponding attribute value
	 * @return {@code true} if the query parameter is not set at all or if both are equal.
	 */
	protected boolean matches(Object queryParameter, Object attribute) {
		return queryParameter == null || queryParameter.equals(attribute);
	}
	
	/**
	 * Checks whether a filter applies.
	 * @param queryParameter the queryParameter list
	 * @param attribute the corresponding attribute value
	 * @return {@code true} if the query parameter is not set at all or if one of the query parameter matches the attribute.
	 */
	protected boolean matches(Object[] queryParameter, Object attribute) {
		return queryParameter == null || queryParameter.length == 0 ||
				(attribute != null && Arrays.asList(queryParameter).contains(attribute));
	}

	/**
	 * Checks whether a like filter applies.
	 * @param queryParameter the queryParameter
	 * @param attribute the corresponding attribute value
	 * @return {@code true} if the query parameter is not set at all or if the attribute is like the query parameters.
	 */
	protected boolean matchesLike(String queryParameter, String attribute) {
		if (queryParameter == null) {
			return true;
		} else if (attribute == null) {
			return queryParameter.replaceAll("[%\\*]", "").length() == 0;
		}
		return attribute.matches(queryParameter.replaceAll("[%\\*]", ".*"));
	}
	
	/**
	 * Null safe compare of two strings.
	 * @param str1 string 1
	 * @param str2 string 2
	 * @return 0 if both strings are equal; -1 if string 1 is less, +1 if string 1 is greater than string 2
	 */
	protected static int compare(final String str1, final String str2) {
		if (str1 == str2) {
			return 0;
		}
		if (str1 == null) {
			return -1;
		}
		if (str2 == null) {
			return 1;
		}
		return str1.compareTo(str2);
	}

	/**
	 * @return true if the passed-in user is currently authenticated
	 */
	protected boolean isAuthenticatedUser(UserEntity user) {
		return isAuthenticatedUser(user.getId());
	}

	/**
	 * @return true if the passed-in userId matches the currently authenticated user
	 */
	protected boolean isAuthenticatedUser(String userId) {
		if (userId == null) {
			return false;
		}
		return userId.equalsIgnoreCase(
				org.camunda.bpm.engine.impl.context.Context.getCommandContext().getAuthenticatedUserId());
	}
	
	/**
	 * Checks if the current is user is authorized to access a specific resource
	 * @param permission the permission, e.g. READ
	 * @param resource the resource type, e.g. GROUP
	 * @param resourceId the ID of the concrete resource to check
	 * @return {@code true} if the current user is authorized to access the given resourceId
	 */
	protected boolean isAuthorized(Permission permission, Resource resource, String resourceId) {
		return !keycloakConfiguration.isAuthorizationCheckEnabled() || org.camunda.bpm.engine.impl.context.Context
				.getCommandContext().getAuthorizationManager().isAuthorized(permission, resource, resourceId);
	}

	protected Set<String> collectSubGroupsIds(String keycloakGroupId) throws JsonException {
		// get members of this group
		ResponseEntity<String> response = restTemplate.exchange(keycloakConfiguration.getKeycloakAdminUrl() + "/groups/" + keycloakGroupId,
				HttpMethod.GET, String.class);
		if (!response.getStatusCode().equals(HttpStatus.OK)) {
			throw new IdentityProviderException("Unable to read group from " + keycloakConfiguration.getKeycloakAdminUrl()
					+ ": HTTP status code " + response.getStatusCode().value());
		}

		JsonObject searchResult = parseAsJsonObject(response.getBody());
		return getSubGroupIds(searchResult);
	}

	protected Set<String> getSubGroupIds(JsonObject group) throws JsonException {
		Set<String> subGroupIds = new HashSet<>();
		JsonArray subGroups = getJsonArray(group, "subGroups");
		if (subGroups != null) {
			for (int i = 0; i < subGroups.size(); i++) {
				JsonObject subGroup = getJsonObjectAtIndex(subGroups, i);
				subGroupIds.add(getJsonString(subGroup, "id"));
				if (subGroup.has("subGroups")) {
					subGroupIds.addAll(getSubGroupIds(subGroup));
				}
			}
		}
		return subGroupIds;
	}

	protected boolean isTenantGroup(JsonObject groupJsonObject) throws JsonException {
		return isTenantGroup(keycloakConfiguration, groupJsonObject);
	}

	private static boolean isTenantGroup(KeycloakConfiguration config, JsonObject result) throws JsonException {
		String tenantRootGroupName = config.getTenantRootGroupName();
		if (!StringUtils.hasLength(tenantRootGroupName))
			return false;
		String root = getContextRoot(config);
		String path = getJsonString(result, "path");
		return StringUtils.startsWithIgnoreCase(path, "/" + root + tenantRootGroupName + "/")
				&& removeStart(path, "/" + root).split("/").length == 2;
	}

	protected String getContextRoot() {
		return getContextRoot(keycloakConfiguration);
	}

	protected static String getContextRoot(KeycloakConfiguration config) {
		if (StringUtils.hasLength(config.getContextRootGroupName())) {
			return config.getContextRootGroupName() + "/";
		} else {
			return "";
		}
	}

	protected <T> List<T> commonElements(Collection<Set<T>> collection) {
		Iterator<Set<T>> it = collection.iterator();
		List<T> commonElements = new ArrayList<>(it.next());
		while (it.hasNext()) {
			commonElements.retainAll(it.next());
		}
		return commonElements;
	}

	public Optional<JsonObject> findUser(ResponseEntity<String> response, String userId)
			throws JsonException {
		return findUser(JsonParser.parseString(response.getBody()), userId);
	}

	public Optional<JsonObject> findUser(JsonElement json, String userId) throws JsonException {
		if (json instanceof JsonArray jsonArr) {
			if (keycloakConfiguration.isUseEmailAsCamundaUserId()) {
				JsonObject result = findFirst(jsonArr, "email", userId);
				return Optional.ofNullable(result);
			} else if (keycloakConfiguration.isUseCustomAttributeAsCamundaUserId()) {
				JsonObject result = findFirst(jsonArr,
						createCustomAttributePredicate(keycloakConfiguration.getUserIdCustomAttribute(), userId));
				return Optional.ofNullable(result);
			} else if (keycloakConfiguration.isUseUsernameAsCamundaUserId()) {
				JsonObject result = findFirst(jsonArr, "username", userId);
				return Optional.ofNullable(result);
			} else {
				JsonObject result = findFirst(jsonArr, "id", userId);
				return Optional.ofNullable(result);
			}
		} else if (json instanceof JsonObject jsonObject) {
			if (keycloakConfiguration.isUseUsernameAsCamundaUserId()) {
				if (userId.equals(getJsonString(jsonObject, "username"))) {
					return Optional.ofNullable(jsonObject);
				}
			} else {
				if (userId.equals(getJsonString(jsonObject, "id"))) {
					return Optional.ofNullable(jsonObject);
				}
			}
		}
		return Optional.empty();
	}

	public Optional<String> extractUserName(ResponseEntity<String> response) throws JsonException {
		return extractUserName(JsonParser.parseString(response.getBody()));
	}

	public Optional<String> extractUserName(JsonElement jsonElement) throws JsonException {
		if (jsonElement instanceof JsonArray jsonArray && !jsonArray.isEmpty()) {
			jsonElement = jsonArray.get(0);
		}
		if (jsonElement instanceof JsonObject jsonObject) {
			if (keycloakConfiguration.isUseUsernameAsCamundaUserId()) {
				return Optional.ofNullable(getJsonString(jsonObject, "username"));
			} else if (keycloakConfiguration.isUseEmailAsCamundaUserId()) {
				return Optional.ofNullable(getJsonString(jsonObject, "email"));
			} else if (keycloakConfiguration.isUseCustomAttributeAsCamundaUserId()) {
				String attr = keycloakConfiguration.getUserIdCustomAttribute();
				JsonObject attributes = jsonObject.getAsJsonObject("attributes");
				if (attributes == null || !StringUtils.hasText(attr))
					return Optional.empty();

				JsonArray attrVal = getJsonArray(attributes, attr);
				if (attrVal != null && !attrVal.isEmpty()) {
					return Optional.ofNullable(attrVal.get(0).getAsString());
				}
			} else {
				return Optional.ofNullable(getJsonString(jsonObject, "id"));
			}
		}
		return Optional.empty();
	}

	protected String removeRootPath(String groupPath) {
		if (!StringUtils.hasLength(groupPath))
			return groupPath;

		String root = appendIfMissing(prependIfMissing(keycloakConfiguration.getContextRootGroupName(), "/"), "/");

		if (groupPath.startsWith(root)) {
			return groupPath.substring(root.length());
		} else if (groupPath.startsWith("/")) {
			return groupPath.substring(1);
		} else {
			return groupPath;
		}

	}

	protected static String replaceGroupPathDelimiterWithSlash(String groupName) {
		if (StringUtils.hasLength(groupName))
			return groupName.replace(GROUP_PATH_DELIMITER, "/");
		return groupName;
	}

	protected static String replaceSlashWithGroupPathDelimiter(String groupName) {
		if (StringUtils.hasLength(groupName))
			return groupName.replace("/", GROUP_PATH_DELIMITER);
		return groupName;
	}

	protected static String prependIfMissing(String value, String prefix) {
		if (!StringUtils.hasLength(prefix)) {
			return value;
		} else if (StringUtils.hasLength(value) && !value.startsWith(prefix)) {
			return prefix + value;
		} else if (!StringUtils.hasLength(value)) {
			return prefix;
		} else {
			return value;
		}
	}

	protected static String appendIfMissing(String value, String suffix) {
		if (!StringUtils.hasLength(suffix)) {
			return value;
		} else if (StringUtils.hasLength(value) && !value.endsWith(suffix)) {
			return value + suffix;
		} else if (!StringUtils.hasLength(value)) {
			return suffix;
		} else {
			return value;
		}
	}

	protected static String removeEnd(String value, String suffix) {
		if (!StringUtils.hasLength(value) || !StringUtils.hasLength(suffix) || !value.endsWith(suffix)) {
			return value;
		} else {
			return value.substring(0, suffix.length());
		}
	}

	protected static String removeStart(String value, String suffix) {
		if (!StringUtils.hasLength(value) || !StringUtils.hasLength(suffix) || !value.startsWith(suffix)) {
			return value;
		} else {
			return value.substring(suffix.length());
		}
	}

}
