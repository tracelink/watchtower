package com.tracelink.appsec.watchtower.core.auth.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.repository.PrivilegesRepository;

/**
 * Service manages creating and finding Privileges in Watchtower
 * 
 * @author csmith
 *
 */
@Service
public class PrivilegeService {

	private PrivilegesRepository privilegeRepo;

	public PrivilegeService(@Autowired PrivilegesRepository privilegeRepo) {
		this.privilegeRepo = privilegeRepo;
	}

	/**
	 * Guarantees that all {@linkplain CorePrivilege} objects are in the database or creates them
	 */
	void ensureDefaultPrivileges() {
		for (CorePrivilege corePriv : CorePrivilege.values()) {
			upsertPrivilege(new PrivilegeEntity().setName(corePriv.getPrivilegeName())
					.setModule("Core").setCategory(corePriv.getCategory())
					.setDescription(corePriv.getDescription()));
		}
	}

	/**
	 * Update an existing entity with the data in this one, or insert this entity if one doesn't
	 * already exist by the same name
	 * 
	 * @param entity the entity with new/corrected information to upsert
	 * @return the entity object that was saved
	 */
	public PrivilegeEntity upsertPrivilege(PrivilegeEntity entity) {
		PrivilegeEntity oldEntity = privilegeRepo.findByName(entity.getName());
		if (oldEntity != null) {
			entity.setId(oldEntity.getId());
		}
		return privilegeRepo.saveAndFlush(entity);
	}

	public List<PrivilegeEntity> getAllPrivileges() {
		return privilegeRepo.findAll(Sort.by("name"));
	}

	public PrivilegeEntity findByName(String name) {
		return privilegeRepo.findByName(name);
	}

}
