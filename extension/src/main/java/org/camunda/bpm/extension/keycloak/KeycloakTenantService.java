package org.camunda.bpm.extension.keycloak;

import static org.camunda.bpm.engine.authorization.Permissions.READ;
import static org.camunda.bpm.engine.authorization.Resources.TENANT;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.getJsonArray;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.getJsonObjectAtIndex;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.getJsonString;
import static org.camunda.bpm.extension.keycloak.json.JsonUtil.parseAsJsonArray;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

import org.camunda.bpm.engine.identity.Tenant;
import org.camunda.bpm.engine.impl.Direction;
import org.camunda.bpm.engine.impl.QueryOrderingProperty;
import org.camunda.bpm.engine.impl.TenantQueryProperty;
import org.camunda.bpm.engine.impl.identity.IdentityProviderException;
import org.camunda.bpm.engine.impl.persistence.entity.TenantEntity;
import org.camunda.bpm.extension.keycloak.json.JsonException;
import org.camunda.bpm.extension.keycloak.rest.KeycloakRestTemplate;
import org.camunda.bpm.extension.keycloak.util.KeycloakPluginLogger;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * Implementation of tenant queries against Keycloak's REST API.
 */
public class KeycloakTenantService extends KeycloakServiceBase {

	/**
	 * Default constructor.
	 * 
	 * @param keycloakConfiguration
	 *            the Keycloak configuration
	 * @param restTemplate
	 *            REST template
	 * @param keycloakContextProvider
	 *            Keycloak context provider
	 */
	public KeycloakTenantService(KeycloakConfiguration keycloakConfiguration, KeycloakRestTemplate restTemplate,
			KeycloakContextProvider keycloakContextProvider) {
		super(keycloakConfiguration, restTemplate, keycloakContextProvider);
	}

	/**
	 * Requests tenants of a specific user.
	 * 
	 * @param query
	 *            the tenant query - including a userId criteria
	 * @return list of matching tenants
	 */
	public List<Tenant> requestTenantsByUserId(CacheableKeycloakTenantQuery query) {
		String userId = query.getUserId();
		List<Tenant> tenantList = new ArrayList<>();

		try {
			// get Keycloak specific userID
			String keyCloakID;
			try {
				keyCloakID = getKeycloakUserID(userId);
			} catch (KeycloakUserNotFoundException e) {
				// user not found: empty search result
				return Collections.emptyList();
			}

			// get tenants of this user
			ResponseEntity<String> response = restTemplate.exchange(
					keycloakConfiguration.getKeycloakAdminUrl() + "/users/" + keyCloakID + "/groups?max=" + getMaxQueryResultSize(),
					HttpMethod.GET, String.class);
			if (!response.getStatusCode().equals(HttpStatus.OK)) {
				throw new IdentityProviderException("Unable to read user tenants from " + keycloakConfiguration.getKeycloakAdminUrl()
						+ ": HTTP status code " + response.getStatusCode().value());
			}

			JsonArray searchResult = parseAsJsonArray(response.getBody());
			for (int i = 0; i < searchResult.size(); i++) {
				JsonObject json = getJsonObjectAtIndex(searchResult, i);
				if (isTenantGroup(json))
					tenantList.add(transformTenant(json));
			}

		} catch (HttpClientErrorException hcee) {
			// if userID is unknown server answers with HTTP 404 not found
			if (hcee.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
				return Collections.emptyList();
			}
			throw hcee;
		} catch (RestClientException | JsonException rce) {
			throw new IdentityProviderException("Unable to query tenants of user " + userId, rce);
		}

		return tenantList;
	}

	/**
	 * Requests tenants.
	 * 
	 * @param query
	 *            the tenant query - not including a userId criteria
	 * @return list of matching tenants
	 */
	public List<Tenant> requestTenantsWithoutUserId(CacheableKeycloakTenantQuery query) {
		List<Tenant> tenantList = new ArrayList<>();

		try {
			// get tenants according to search criteria
			ResponseEntity<String> response;

			if (StringUtils.hasLength(query.getId())) {
				response = requestTenantById(query.getId());
			} else if (query.getIds() != null && query.getIds().length == 1) {
				response = requestTenantById(query.getIds()[0]);
			} else {
				String groupFilter = createTenantsSearchFilter(query); // only pre-filter of names possible
				response = restTemplate.exchange(keycloakConfiguration.getKeycloakAdminUrl() + "/groups" + groupFilter, HttpMethod.GET,
						String.class);
			}
			if (!response.getStatusCode().equals(HttpStatus.OK)) {
				throw new IdentityProviderException("Unable to read tenants from " + keycloakConfiguration.getKeycloakAdminUrl()
						+ ": HTTP status code " + response.getStatusCode().value());
			}

			JsonArray searchResult;
			boolean flatten = false;
			if (StringUtils.hasLength(query.getId())) {
				searchResult = parseAsJsonArray(response.getBody());
			} else {
				// for non ID queries search in subgroups as well
				searchResult = parseAsJsonArray(response.getBody());
				flatten = true;
			}

			if (StringUtils.hasLength(query.getGroupId()))
				filterSubGroup(query, searchResult);

			if (flatten)
				searchResult = flattenSubGroups(searchResult, new JsonArray());

			for (int i = 0; i < searchResult.size(); i++) {
				JsonObject json = getJsonObjectAtIndex(searchResult, i);
				if (isTenantGroup(json))
					tenantList.add(transformTenant(json));
			}

		} catch (RestClientException | JsonException rce) {
			throw new IdentityProviderException("Unable to query tenants", rce);
		}

		return tenantList;
	}

	/**
	 * Post processes a Keycloak query result.
	 * 
	 * @param query
	 *            the original query
	 * @param tenantList
	 *            the full list of results returned from Keycloak without client side filters
	 * @param resultLogger
	 *            the log accumulator
	 * @return final result with client side filtered, sorted and paginated list of tenants
	 */
	public List<Tenant> postProcessResults(KeycloakTenantQuery query, List<Tenant> tenantList, StringBuilder resultLogger) {
		// apply client side filtering
		Stream<Tenant> processed = tenantList.stream().filter(tenant -> isValid(query, tenant, resultLogger));

		// sort tenants according to query criteria
		if (!query.getOrderingProperties().isEmpty()) {
			processed = processed.sorted(new TenantComparator(query.getOrderingProperties()));
		}

		// paging
		if ((query.getFirstResult() > 0) || (query.getMaxResults() < Integer.MAX_VALUE)) {
			processed = processed.skip(query.getFirstResult()).limit(query.getMaxResults());
		}

		// tenant queries in Keycloak do not consider the max attribute within the search request
		return processed.limit(keycloakConfiguration.getMaxResultSize()).toList();
	}

	private boolean filterSubGroup(CacheableKeycloakTenantQuery query, JsonArray groups) throws JsonException {
		if (groups == null || groups.isEmpty())
			return false;
		boolean returnValue = false;
		try {
			Iterator<JsonElement> itr = groups.iterator();
			while (itr.hasNext()) {
				JsonElement el = itr.next();
				if (el instanceof JsonObject group) {
					if (isGroupIdEquals(query.getGroupId(), group)) {
						returnValue = true;
					} else {
						boolean x = filterSubGroup(query, getJsonArray(group, "subGroups"));
						if (!x)
							itr.remove();
						returnValue |= x;
					}
				}
			}
		} catch (JsonException e) {
			// ignore
		}
		return returnValue;
	}

	private boolean isGroupIdEquals(String groupId, JsonObject group) throws JsonException {
		if (keycloakConfiguration.isUseGroupPathAsCamundaGroupId()) {
			String name = getJsonString(group, "name");
			if (StringUtils.hasLength(name) && name.equals(groupId))
				return true;
		} else {
			String id = getJsonString(group, "id");
			if (StringUtils.hasLength(id) && id.equals(groupId))
				return true;
		}
		return false;
	}

	/**
	 * Post processing query filter. Checks if a single tenant is valid.
	 * 
	 * @param query
	 *            the original query
	 * @param tenant
	 *            the tenant to validate
	 * @param resultLogger
	 *            the log accumulator
	 * @return a boolean indicating if the tenant is valid for current query
	 */
	private boolean isValid(KeycloakTenantQuery query, Tenant tenant, StringBuilder resultLogger) {
		// client side check of further query filters
		if (!matches(query.getId(), tenant.getId()))
			return false;
		if (!matches(query.getIds(), tenant.getId()))
			return false;
		if (!matches(query.getName(), tenant.getName()))
			return false;
		if (!matchesLike(query.getNameLike(), tenant.getName()))
			return false;

		// authenticated user is always allowed to query his own tenants
		// otherwise READ authentication is required
		boolean isAuthenticatedUser = isAuthenticatedUser(query.getUserId());
		if (isAuthenticatedUser || isAuthorized(READ, TENANT, tenant.getId())) {
			if (KeycloakPluginLogger.INSTANCE.isDebugEnabled()) {
				resultLogger.append(tenant);
				resultLogger.append(", ");
			}
			return true;
		}

		return false;
	}

	/**
	 * Creates an Keycloak tenant search filter query
	 * 
	 * @param query
	 *            the tenant query
	 * @return request query
	 */
	private String createTenantsSearchFilter(CacheableKeycloakTenantQuery query) {
		StringBuilder filter = new StringBuilder();
		if (StringUtils.hasLength(query.getName())) {
			addArgument(filter, "search", query.getName());
		}
		if (StringUtils.hasLength(query.getNameLike())) {
			addArgument(filter, "search", query.getNameLike().replaceAll("[%,\\*]", ""));
		}
		// addArgument(filter, "max", getMaxQueryResultSize());
		if (filter.length() > 0) {
			filter.insert(0, "?");
			String result = filter.toString();
			KeycloakPluginLogger.INSTANCE.tenantQueryFilter(result);
			return result;
		}
		return "";
	}

	/**
	 * Converts a result consisting of a potential hierarchy of tenants into a flattened list of tenants.
	 * 
	 * @param tenants
	 *            the original structured hierarchy of tenants
	 * @param result
	 *            recursive result
	 * @return flattened list of all tenants in this hierarchy
	 * @throws JsonException
	 *             in case of errors
	 */
	private JsonArray flattenSubGroups(JsonArray groups, JsonArray result) throws JsonException {
		if (groups == null)
			return result;
		for (int i = 0; i < groups.size(); i++) {
			JsonObject group = getJsonObjectAtIndex(groups, i);
			JsonArray subGroups;
			try {
				subGroups = getJsonArray(group, "subGroups");
				group.remove("subGroups");
				result.add(group);
				flattenSubGroups(subGroups, result);
			} catch (JsonException e) {
				result.add(group);
			}
		}
		return result;
	}

	/**
	 * Requests data of single tenant.
	 * 
	 * @param tenantId
	 *            the ID of the requested tenant
	 * @return response consisting of a list containing the one tenant
	 * @throws RestClientException
	 */
	private ResponseEntity<String> requestTenantById(String tenantId) throws RestClientException {
		try {

			String tenantRootGroupName = keycloakConfiguration.getTenantRootGroupName();
			String tenantSearch;
			if (StringUtils.hasLength(tenantRootGroupName) && keycloakConfiguration.isUseGroupNameAsTenantId()) {
				String keycloakName = tenantRootGroupName + "/" + tenantId;
				tenantSearch = "/group-by-path/" + keycloakName;
			} else {
				tenantSearch = "/groups/" + tenantId;
			}

			ResponseEntity<String> response = restTemplate.exchange(keycloakConfiguration.getKeycloakAdminUrl() + tenantSearch,
					HttpMethod.GET, String.class);
			String result = "[" + response.getBody() + "]";
			return new ResponseEntity<>(result, response.getHeaders(), response.getStatusCode());
		} catch (HttpClientErrorException hcee) {
			if (hcee.getStatusCode().equals(HttpStatus.NOT_FOUND)) {
				String result = "[]";
				return new ResponseEntity<>(result, HttpStatus.OK);
			}
			throw hcee;
		}
	}

	/**
	 * Maps a Keycloak JSON result to a Tenant object
	 * 
	 * @param result
	 *            the Keycloak JSON result
	 * @return the Tenant object
	 * @throws JsonException
	 *             in case of errors
	 */
	private TenantEntity transformTenant(JsonObject result) throws JsonException {
		TenantEntity tenant = new TenantEntity();

		if (keycloakConfiguration.isUseGroupNameAsTenantId()) {
			String temp = getJsonString(result, "path");
			tenant.setId(temp.substring(temp.indexOf("/", 1) + 1)); // remove trailing '/'

		} else {
			tenant.setId(getJsonString(result, "id"));
		}

		tenant.setName(getJsonString(result, "name"));
		return tenant;
	}

	/**
	 * Helper for client side tenant ordering.
	 */
	private static class TenantComparator implements Comparator<Tenant> {
		private final static int GROUP_ID = 0;
		private final static int NAME = 1;

		private final int[] order;
		private final boolean[] desc;

		public TenantComparator(List<QueryOrderingProperty> orderList) {
			// Prepare query ordering
			this.order = new int[orderList.size()];
			this.desc = new boolean[orderList.size()];
			for (int i = 0; i < orderList.size(); i++) {
				QueryOrderingProperty qop = orderList.get(i);
				if (qop.getQueryProperty().equals(TenantQueryProperty.GROUP_ID)) {
					order[i] = GROUP_ID;
				} else if (qop.getQueryProperty().equals(TenantQueryProperty.NAME)) {
					order[i] = NAME;
				} else {
					order[i] = -1;
				}
				desc[i] = Direction.DESCENDING.equals(qop.getDirection());
			}
		}

		@Override
		public int compare(Tenant g1, Tenant g2) {
			int c = 0;
			for (int i = 0; i < order.length; i++) {
				switch (order[i]) {
				case GROUP_ID:
					c = KeycloakServiceBase.compare(g1.getId(), g2.getId());
					break;
				case NAME:
					c = KeycloakServiceBase.compare(g1.getName(), g2.getName());
					break;
				default:
					// do nothing
				}
				if (c != 0) {
					return desc[i] ? -c : c;
				}
			}
			return c;
		}
	}

}
