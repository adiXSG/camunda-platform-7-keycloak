package org.camunda.bpm.extension.keycloak.test;

import java.util.List;

import org.camunda.bpm.engine.ProcessEngineConfiguration;
import org.camunda.bpm.engine.identity.Tenant;
import org.camunda.bpm.engine.identity.User;
import org.camunda.bpm.engine.impl.cfg.ProcessEngineConfigurationImpl;
import org.camunda.bpm.engine.impl.test.PluggableProcessEngineTestCase;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * Tenant query test for the Keycloak identity provider. Flag useGroupPathAsCamundaGroupId enabled.
 */
public class KeycloakUseGroupNameAsTenantIdQueryTest extends AbstractKeycloakIdentityProviderTest {

	public static Test suite() {
		return new TestSetup(new TestSuite(KeycloakUseGroupNameAsTenantIdQueryTest.class)) {
			// @BeforeClass
			@Override
			protected void setUp() throws Exception {
				ProcessEngineConfigurationImpl config = (ProcessEngineConfigurationImpl) ProcessEngineConfiguration
						.createProcessEngineConfigurationFromResource("camunda.useGroupNameAsCamundaTenantId.cfg.xml");
				configureKeycloakIdentityProviderPlugin(config);
				PluggableProcessEngineTestCase.cachedProcessEngine = config.buildProcessEngine();
			}

			// @AfterClass
			@Override
			protected void tearDown() throws Exception {
				PluggableProcessEngineTestCase.cachedProcessEngine.close();
				PluggableProcessEngineTestCase.cachedProcessEngine = null;
			}
		};
	}

	// ------------------------------------------------------------------------
	// Tenant Query tests
	// ------------------------------------------------------------------------
	public void testFilterByTenantId() {
		Tenant tenant = identityService.createTenantQuery().tenantId(GROUP_NAME_TENANT_TENANT1).singleResult();
		assertNotNull(tenant);

		// validate result
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getName());

		tenant = identityService.createTenantQuery().tenantId("whatever").singleResult();
		assertNull(tenant);
	}

	public void testFilterByChildGroupId() {
		Tenant tenant = identityService.createTenantQuery().groupMember(GROUP_ID_TENANT_TENANT3_TEAM).singleResult();
		assertNotNull(tenant);

		// validate result
		assertEquals(GROUP_NAME_TENANT_TENANT3, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT3, tenant.getName());
	}

	public void testFilterByGroupId() {
		List<Tenant> result = identityService.createTenantQuery().groupMember(GROUP_ID_TENANT_TENANT3_USERS).list();
		assertEquals(1, result.size());
	}

	public void testFilterByUserIdMemberOfTenants() {
		List<Tenant> tenants = identityService.createTenantQuery().userMember("max.miller@foo.bar").list();
		assertEquals(2, tenants.size());

		for (Tenant tenant : tenants) {
			if (!tenant.getId().equals(GROUP_NAME_TENANT_TENANT1) && !tenant.getId().equals(GROUP_NAME_TENANT_TENANT2)) {
				fail();
			}
		}

	}

	public void testFilterByTenantIdIn() {
		List<Tenant> tenants = identityService.createTenantQuery().tenantIdIn(GROUP_NAME_TENANT_TENANT1, GROUP_NAME_TENANT_TENANT2).list();

		assertEquals(2, tenants.size());
		for (Tenant tenant : tenants) {
			if (!tenant.getName().equals(GROUP_NAME_TENANT_TENANT1) && !tenant.getName().equals(GROUP_NAME_TENANT_TENANT2)) {
				fail();
			}
		}
	}

	public void testFilterByTenantIdInAndUserId() {
		Tenant tenant = identityService.createTenantQuery().tenantIdIn(GROUP_NAME_TENANT_TENANT1, GROUP_NAME_TENANT_TENANT2)
				.userMember("jos.tanner@foo.bar").singleResult();
		assertNotNull(tenant);
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getName());
	}

	public void testFilterByTenantIdInAndGroupId() {
		Tenant tenant = identityService.createTenantQuery().tenantIdIn(GROUP_NAME_TENANT_TENANT1, GROUP_NAME_TENANT_TENANT3)
				.groupMember(GROUP_ID_TENANT_TENANT3_TEAM).singleResult();
		assertNotNull(tenant);
		assertEquals(GROUP_NAME_TENANT_TENANT3, tenant.getName());
	}

	public void testFilterByGroupName() {
		Tenant tenant = identityService.createTenantQuery().tenantName(GROUP_NAME_TENANT_TENANT1).singleResult();
		assertNotNull(tenant);

		// validate result
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getName());

		tenant = identityService.createTenantQuery().tenantName("whatever").singleResult();
		assertNull(tenant);
	}

	public void testFilterByTenantNameLike() {
		Tenant tenant = identityService.createTenantQuery().tenantNameLike(GROUP_NAME_TENANT_TENANT1.substring(0, 3) + "*").singleResult();
		assertNotNull(tenant);

		// validate result
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT1, tenant.getName());

		tenant = identityService.createTenantQuery().tenantNameLike("what*").singleResult();
		assertNull(tenant);
	}

	public void testFilterByGroupNameAndGroupNameLike() {
		Tenant tenant = identityService.createTenantQuery().tenantNameLike(GROUP_NAME_TENANT_TENANT3.substring(0, 2) + "*")
				.tenantName(GROUP_NAME_TENANT_TENANT3).singleResult();
		assertNotNull(tenant);

		// validate result
		assertEquals(GROUP_NAME_TENANT_TENANT3, tenant.getId());
		assertEquals(GROUP_NAME_TENANT_TENANT3, tenant.getName());
	}

	public void testFilterByUserMember() {
		List<Tenant> list = identityService.createTenantQuery().userMember("camunda@accso.de").list();
		assertEquals(0, list.size());
		list = identityService.createTenantQuery().userMember("max.miller@foo.bar").list();
		assertEquals(2, list.size());
		list = identityService.createTenantQuery().userMember("jos.tanner@foo.bar").list();
		assertEquals(1, list.size());
		list = identityService.createTenantQuery().userMember("non-existing").list();
		assertEquals(0, list.size());
	}

	public void testOrderByNameTenantId() {
		List<Tenant> groupList = identityService.createTenantQuery().orderByTenantId().desc().list();
		assertEquals(3, groupList.size());
		assertTrue(groupList.get(0).getId().compareTo(groupList.get(1).getId()) > 0);
		assertTrue(groupList.get(1).getId().compareTo(groupList.get(2).getId()) > 0);
	}

	public void testOrderByTenantName() {
		List<Tenant> groupList = identityService.createTenantQuery().orderByTenantName().list();
		assertEquals(3, groupList.size());
		assertTrue(groupList.get(0).getName().compareTo(groupList.get(1).getName()) < 0);
		assertTrue(groupList.get(1).getName().compareTo(groupList.get(2).getName()) < 0);
	}

	// ------------------------------------------------------------------------
	// User Query tests
	// ------------------------------------------------------------------------

	public void testFilterUserByTenantId() {
		List<User> result = identityService.createUserQuery().memberOfTenant(GROUP_NAME_TENANT_TENANT1).list();
		assertEquals(2, result.size());

		result = identityService.createUserQuery().memberOfTenant("non-exist").list();
		assertEquals(0, result.size());
	}

	public void testFilterUserByChildGroupId() {
		List<User> result = identityService.createUserQuery().memberOfTenant(GROUP_NAME_TENANT_TENANT3)
				.memberOfGroup(GROUP_ID_TENANT_TENANT3_TEAM).list();
		assertEquals(1, result.size());
	}

	public void testFilterUserByTenantIdAndFirstname() {
		List<User> result = identityService.createUserQuery().memberOfTenant(GROUP_NAME_TENANT_TENANT1).userFirstName("Max").list();
		assertEquals(1, result.size());
	}

	public void testFilterUserByGroupIdAndId() {
		List<User> result = identityService.createUserQuery().memberOfTenant(GROUP_NAME_TENANT_TENANT1).userId("max.miller@foo.bar").list();
		assertEquals(1, result.size());
	}

	public void testFilterUserByChildByGroupIdAndGroupIdAndId() {
		List<User> result = identityService.createUserQuery().memberOfTenant(GROUP_NAME_TENANT_TENANT3)
				.memberOfGroup(GROUP_ID_TENANT_TENANT3_TEAM).userId("jane.doe@fbar.com").list();
		assertEquals(1, result.size());
	}

	public void testFilterUserByTenantIdAndLastname() {
		List<User> result = identityService.createUserQuery().memberOfTenant(GROUP_NAME_TENANT_TENANT1).userLastName("Miller").list();
		assertEquals(1, result.size());
	}

	public void testFilterUserByTenantIdAndEmail() {
		List<User> result = identityService.createUserQuery().memberOfTenant(GROUP_NAME_TENANT_TENANT1).userEmail("jos.tanner@foo.bar")
				.list();
		assertEquals(1, result.size());
	}

	public void testFilterUserByTenantIdAndEmailLike() {
		List<User> result = identityService.createUserQuery().memberOfTenant(GROUP_NAME_TENANT_TENANT1).userEmailLike("*nner@foo.bar")
				.list();
		assertEquals(1, result.size());
	}

	public void testFilterUserByTenantIdSimilarToClientName() {
		User user = identityService.createUserQuery().memberOfTenant(GROUP_NAME_TENANT_TENANT2).singleResult();
		assertNotNull(user);
		assertEquals("max.miller@foo.bar", user.getId());
	}

}
