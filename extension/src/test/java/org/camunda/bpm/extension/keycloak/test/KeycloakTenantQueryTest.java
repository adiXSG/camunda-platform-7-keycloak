package org.camunda.bpm.extension.keycloak.test;

import static org.camunda.bpm.engine.authorization.Authorization.AUTH_TYPE_GRANT;
import static org.junit.Assert.assertNotEquals;

import java.util.List;

import org.camunda.bpm.engine.authorization.Authorization;
import org.camunda.bpm.engine.authorization.Permission;
import org.camunda.bpm.engine.authorization.Resource;
import org.camunda.bpm.engine.identity.Tenant;
import org.camunda.bpm.extension.keycloak.CacheableKeycloakTenantQuery;
import org.camunda.bpm.extension.keycloak.KeycloakTenantQuery;

/**
 * Tests tenant queries.
 */
public class KeycloakTenantQueryTest extends AbstractKeycloakIdentityProviderTest {

	public void testQueryNoFilter() {
		List<Tenant> tenantList = identityService.createTenantQuery().list();
		assertEquals(3, tenantList.size());
	}

	public void testQueryUnlimitedList() {
		List<Tenant> tenantList = identityService.createTenantQuery().unlimitedList();
		assertEquals(3, tenantList.size());
	}

	public void testQueryPaging() {
		// First page
		List<Tenant> result = identityService.createTenantQuery().listPage(0, 2);
		assertEquals(2, result.size());

		// Next page
		List<Tenant> resultNext = identityService.createTenantQuery().listPage(2, 2);
		assertEquals(1, resultNext.size());

		// Next page
		List<Tenant> resultLast = identityService.createTenantQuery().listPage(2, 4);
		assertEquals(1, resultLast.size());

		// unique results
		assertEquals(0, result.stream().filter(tenant -> resultNext.contains(tenant)).count());
		assertEquals(0, result.stream().filter(tenant -> resultLast.contains(tenant)).count());
	}

	public void testFilterByTenantId() {
		Tenant tenant = identityService.createTenantQuery().tenantId(GROUP_ID_TENANT_TENANT1).singleResult();
		assertNotNull(tenant);

		// validate result
		assertEquals(GROUP_ID_TENANT_TENANT1, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getName());

		tenant = identityService.createTenantQuery().tenantId("whatever").singleResult();
		assertNull(tenant);
	}

	public void testFilterByUserId() {
		List<Tenant> result = identityService.createTenantQuery().userMember("jos.tanner@foo.bar").list();
		assertEquals(1, result.size());
	}

	public void testAuthenticatedUserCanQueryOwnTenants() {
		try {
			processEngineConfiguration.setAuthorizationEnabled(true);
			identityService.setAuthenticatedUserId("jos.tanner@foo.bar");

			assertEquals(0, identityService.createTenantQuery().userMember("max.miller@foo.bar").count());
			assertEquals(1, identityService.createTenantQuery().userMember("jos.tanner@foo.bar").count());

		} finally {
			processEngineConfiguration.setAuthorizationEnabled(false);
			identityService.clearAuthentication();
		}
	}

	public void testFilterByTenantIdInMulti() {
		List<Tenant> tenants = identityService.createTenantQuery().tenantIdIn(GROUP_ID_TENANT_TENANT1, GROUP_ID_TENANT_TENANT2).list();

		assertEquals(2, tenants.size());
		for (Tenant tenant : tenants) {
			if (!tenant.getName().equals(GROUP_NAME_TENANT_TENANT1) && !tenant.getName().equals(GROUP_NAME_TENANT_TENANT2)) {
				fail();
			}
		}

		tenants = identityService.createTenantQuery().tenantIdIn(GROUP_ID_TENANT_TENANT1, "non-existent").list();
		assertEquals(1, tenants.size());
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenants.get(0).getName());

		tenants = identityService.createTenantQuery().tenantIdIn(GROUP_ID_TENANT_TENANT1).list();
		assertEquals(1, tenants.size());
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenants.get(0).getName());

	}

	public void testFilterByTenantIdInSingle() {
		Tenant tenant = identityService.createTenantQuery().tenantIdIn(GROUP_ID_TENANT_TENANT1).singleResult();
		assertNotNull(tenant);
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getName());
	}

	public void testFilterByTenantIdInAndUserId() {
		Tenant tenant = identityService.createTenantQuery().tenantIdIn(GROUP_ID_TENANT_TENANT1, GROUP_ID_TENANT_TENANT2)
				.userMember("jos.tanner@foo.bar").singleResult();
		assertNotNull(tenant);
		assertEquals(GROUP_ID_TENANT_TENANT1, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getName());
	}

	public void testFilterByTenantName() {
		Tenant tenant = identityService.createTenantQuery().tenantName(GROUP_NAME_TENANT_TENANT2).singleResult();
		assertNotNull(tenant);

		// validate result
		assertEquals(GROUP_ID_TENANT_TENANT2, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT2, tenant.getName());

		tenant = identityService.createTenantQuery().tenantName("whatever").singleResult();
		assertNull(tenant);
	}

	public void testFilterByTenantNameLike() {
		Tenant tenant = identityService.createTenantQuery().tenantNameLike(GROUP_NAME_TENANT_TENANT1.substring(0, 4) + "*").singleResult();
		assertNotNull(tenant);

		// validate result
		assertEquals(GROUP_ID_TENANT_TENANT1, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getName());

		tenant = identityService.createTenantQuery().tenantNameLike("what*").singleResult();
		assertNull(tenant);
	}

	public void testFilterByTenantNameAndTenantNameLike() {
		Tenant tenant = identityService.createTenantQuery().tenantNameLike(GROUP_NAME_TENANT_TENANT1.substring(0, 2) + "*")
				.tenantName(GROUP_NAME_TENANT_TENANT1).singleResult();
		assertNotNull(tenant);

		// validate result
		assertEquals(GROUP_ID_TENANT_TENANT1, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getName());
	}

	public void testFilterByTenantMember() {
		List<Tenant> list = identityService.createTenantQuery().userMember("max.miller@foo.bar").list();
		assertEquals(2, list.size());
		list = identityService.createTenantQuery().userMember("jos.tanner@foo.bar").list();
		assertEquals(1, list.size());
		list = identityService.createTenantQuery().userMember("non-existing").list();
		assertEquals(0, list.size());
	}

	public void testOrderByTenantId() {
		List<Tenant> tenantList = identityService.createTenantQuery().orderByTenantId().desc().list();
		assertEquals(3, tenantList.size());
		assertTrue(tenantList.get(0).getId().compareTo(tenantList.get(1).getId()) > 0);
		assertTrue(tenantList.get(1).getId().compareTo(tenantList.get(2).getId()) > 0);
	}

	public void testOrderByTenantName() {
		List<Tenant> tenantList = identityService.createTenantQuery().orderByTenantName().list();
		assertEquals(3, tenantList.size());
		assertTrue(tenantList.get(0).getName().compareTo(tenantList.get(1).getName()) < 0);
		assertTrue(tenantList.get(1).getName().compareTo(tenantList.get(2).getName()) < 0);
	}

	public void testQueryObjectEquality() {

		KeycloakTenantQuery q1 = (KeycloakTenantQuery) identityService.createTenantQuery();
		KeycloakTenantQuery q2 = (KeycloakTenantQuery) identityService.createTenantQuery();

		assertNotSame(q1, q2); // not the same object (by identity)
		assertNotEquals(q1, q2); // not equal

		assertNotSame(CacheableKeycloakTenantQuery.of(q1), CacheableKeycloakTenantQuery.of(q2)); // not the same object
		assertEquals(CacheableKeycloakTenantQuery.of(q1), CacheableKeycloakTenantQuery.of(q2)); // but they are equal

		q1.tenantId("id1");

		// not equal because first query has a filter
		assertNotEquals(CacheableKeycloakTenantQuery.of(q1), CacheableKeycloakTenantQuery.of(q2));

		q2.tenantId("id1");

		// equal now because second query also has same filter
		assertEquals(CacheableKeycloakTenantQuery.of(q1), CacheableKeycloakTenantQuery.of(q2));
	}

	protected void createGrantAuthorization(Resource resource, String resourceId, String userId, Permission... permissions) {
		Authorization authorization = createAuthorization(AUTH_TYPE_GRANT, resource, resourceId);
		authorization.setUserId(userId);
		for (Permission permission : permissions) {
			authorization.addPermission(permission);
		}
		authorizationService.saveAuthorization(authorization);
	}

	protected Authorization createAuthorization(int type, Resource resource, String resourceId) {
		Authorization authorization = authorizationService.createNewAuthorization(type);

		authorization.setResource(resource);
		if (resourceId != null) {
			authorization.setResourceId(resourceId);
		}

		return authorization;
	}

}
