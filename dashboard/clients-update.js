// Client management functions

let CLIENTS = [];
let currentTab = 'candidates';
let workflowState = {
  step: 'company',
  company: '',
  address: '',
  postcode: '',
  contacts: []
};

function chooseDashboard(view) {
  document.getElementById('splashScreen').classList.add('hidden');
  switchTab(view);
}

async function loadClients() {
  try {
    const res = await fetch(`${API_BASE}/api/clients`);
    if (res.ok) {
      const data = await res.json();
      CLIENTS = data.data || [];
      renderClientsView();
    }
  } catch (e) {
    console.error('Error loading clients:', e);
  }
}

function renderClientsView() {
  const grid = document.getElementById('clientsGrid');
  if (!grid) return;
  
  // Group clients by company
  const byCompany = {};
  CLIENTS.forEach(client => {
    if (!byCompany[client.company]) {
      byCompany[client.company] = {
        company: client.company,
        address: client.address,
        postcode: client.postcode,
        contacts: []
      };
    }
    if (client.contactName) {
      byCompany[client.company].contacts.push({
        name: client.contactName,
        title: client.jobTitle,
        email: client.email,
        phone: client.phone
      });
    }
  });

  const companies = Object.values(byCompany);
  
  if (companies.length === 0) {
    grid.innerHTML = '<div id="noClients" style="grid-column:1/-1;">No clients yet. Click "Add Client" to get started.</div>';
    return;
  }

  grid.innerHTML = companies.map(client => `
    <div class="client-card">
      <h3>${escapeHtml(client.company)}</h3>
      <div class="detail">
        <span>${escapeHtml(client.address)}</span>
        ${client.postcode ? '<br>' + escapeHtml(client.postcode) : ''}
      </div>
      <div style="margin-top:14px;border-top:1px solid var(--border);padding-top:12px;">
        <div style="font-size:11px;color:var(--gold);font-weight:500;margin-bottom:10px;">${client.contacts.length} Contact${client.contacts.length !== 1 ? 's' : ''}</div>
        ${client.contacts.map(contact => `
          <div class="contact-item" style="background:none;border:none;padding:0 0 10px 0;margin:0;">
            <div class="contact-item-info">
              <div class="contact-item-name">${escapeHtml(contact.name)}</div>
              ${contact.title ? '<div class="contact-item-title">' + escapeHtml(contact.title) + '</div>' : ''}
              <div style="font-size:12px;color:var(--gold);margin-top:4px;">
                <a href="mailto:${escapeHtml(contact.email)}" style="text-decoration:none;">${escapeHtml(contact.email)}</a>
              </div>
              ${contact.phone ? '<div style="font-size:12px;color:#999;margin-top:2px;"><a href="tel:' + escapeHtml(contact.phone) + '" style="text-decoration:none;">' + escapeHtml(contact.phone) + '</a></div>' : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
}

function openAddClientModal() {
  workflowState = {
    step: 'company',
    company: '',
    address: '',
    postcode: '',
    contacts: []
  };
  showWorkflowStep('company');
  document.getElementById('addClientWorkflow').classList.add('visible');
}

function showWorkflowStep(step) {
  workflowState.step = step;
  const content = document.getElementById('workflowContent');
  
  if (step === 'company') {
    content.innerHTML = `
      <div class="workflow-header">
        <h2>Add New Client</h2>
        <div class="workflow-step-indicator">Step 1 of 3</div>
      </div>
      <div class="workflow-field">
        <label>Company name *</label>
        <input type="text" id="wf-company" placeholder="e.g. Ceasefire Industries" value="${escapeHtml(workflowState.company)}">
      </div>
      <div class="workflow-actions">
        <button class="cancel" onclick="closeModal('addClientWorkflow')">Cancel</button>
        <button class="next" onclick="workflowNext('company')">Next</button>
      </div>
    `;
    setTimeout(() => document.getElementById('wf-company').focus(), 100);
  }
  
  else if (step === 'address') {
    content.innerHTML = `
      <div class="workflow-header">
        <h2>Company Location</h2>
        <div class="workflow-step-indicator">Step 2 of 3</div>
      </div>
      <div class="workflow-field">
        <label>Address</label>
        <input type="text" id="wf-address" placeholder="e.g. 286b Chase Road" value="${escapeHtml(workflowState.address)}">
      </div>
      <div class="workflow-field">
        <label>Postcode</label>
        <input type="text" id="wf-postcode" placeholder="e.g. N14 6HF" value="${escapeHtml(workflowState.postcode)}">
      </div>
      <div class="workflow-actions">
        <button class="cancel" onclick="workflowBack()">Back</button>
        <button class="next" onclick="workflowNext('address')">Next</button>
      </div>
    `;
    setTimeout(() => document.getElementById('wf-address').focus(), 100);
  }
  
  else if (step === 'contacts') {
    let contactsHtml = '';
    if (workflowState.contacts.length > 0) {
      contactsHtml = `
        <div class="contacts-added">
          ${workflowState.contacts.map((contact, idx) => `
            <div class="contact-item">
              <div class="contact-item-info">
                <div class="contact-item-name">${escapeHtml(contact.name)}</div>
                <div class="contact-item-title">${escapeHtml(contact.jobTitle)}</div>
                <div class="contact-item-email">${escapeHtml(contact.email)}</div>
                ${contact.phone ? '<div style="font-size:12px;color:#999;margin-top:2px;">' + escapeHtml(contact.phone) + '</div>' : ''}
              </div>
              <button class="contact-item-remove" onclick="removeContact(${idx})">×</button>
            </div>
          `).join('')}
        </div>
      `;
    }
    
    content.innerHTML = `
      <div class="workflow-header">
        <h2>Add Contacts</h2>
        <div class="workflow-step-indicator">Step 3 of 3</div>
      </div>
      ${contactsHtml}
      <div class="workflow-field">
        <label>Contact name *</label>
        <input type="text" id="wf-contact-name" placeholder="e.g. Sarah Jones">
      </div>
      <div class="workflow-field">
        <label>Job title</label>
        <input type="text" id="wf-contact-title" placeholder="e.g. Recruitment Manager">
      </div>
      <div class="workflow-field">
        <label>Email *</label>
        <input type="email" id="wf-contact-email" placeholder="sarah@company.com">
      </div>
      <div class="workflow-field">
        <label>Phone</label>
        <input type="tel" id="wf-contact-phone" placeholder="07000 000000">
      </div>
      <div class="workflow-actions">
        <button class="cancel" onclick="workflowBack()">Back</button>
        <button class="cancel" onclick="addAnotherContact()" style="background:var(--lightbg);border-color:var(--border);">+ Add Another</button>
        <button class="next" onclick="workflowNext('contacts')">Finish</button>
      </div>
    `;
    setTimeout(() => document.getElementById('wf-contact-name').focus(), 100);
  }
}

function workflowNext(currentStep) {
  if (currentStep === 'company') {
    const company = document.getElementById('wf-company').value.trim();
    if (!company) {
      showToast('Company name is required');
      return;
    }
    workflowState.company = company;
    showWorkflowStep('address');
  }
  
  else if (currentStep === 'address') {
    workflowState.address = document.getElementById('wf-address').value.trim();
    workflowState.postcode = document.getElementById('wf-postcode').value.trim();
    showWorkflowStep('contacts');
  }
  
  else if (currentStep === 'contacts') {
    const contactName = document.getElementById('wf-contact-name').value.trim();
    const email = document.getElementById('wf-contact-email').value.trim();
    
    if (!contactName || !email) {
      showToast('Contact name and email are required');
      return;
    }
    
    if (workflowState.contacts.length === 0) {
      showToast('Add at least one contact');
      return;
    }
    
    saveClientWithContacts();
  }
}

function workflowBack() {
  if (workflowState.step === 'address') {
    showWorkflowStep('company');
  } else if (workflowState.step === 'contacts') {
    showWorkflowStep('address');
  }
}

function addAnotherContact() {
  const contactName = document.getElementById('wf-contact-name').value.trim();
  const contactTitle = document.getElementById('wf-contact-title').value.trim();
  const email = document.getElementById('wf-contact-email').value.trim();
  const phone = document.getElementById('wf-contact-phone').value.trim();
  
  if (!contactName || !email) {
    showToast('Contact name and email are required');
    return;
  }
  
  workflowState.contacts.push({
    name: contactName,
    jobTitle: contactTitle,
    email: email,
    phone: phone
  });
  
  // Clear fields and refresh
  document.getElementById('wf-contact-name').value = '';
  document.getElementById('wf-contact-title').value = '';
  document.getElementById('wf-contact-email').value = '';
  document.getElementById('wf-contact-phone').value = '';
  showWorkflowStep('contacts');
}

function removeContact(idx) {
  workflowState.contacts.splice(idx, 1);
  showWorkflowStep('contacts');
}

async function saveClientWithContacts() {
  try {
    // Save first contact with company info
    const firstContact = workflowState.contacts[0];
    const res = await fetch(`${API_BASE}/api/clients`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        company: workflowState.company,
        address: workflowState.address,
        postcode: workflowState.postcode,
        contactName: firstContact.name,
        jobTitle: firstContact.jobTitle,
        email: firstContact.email,
        phone: firstContact.phone,
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Failed to add client');
    }

    // Save additional contacts
    for (let i = 1; i < workflowState.contacts.length; i++) {
      const contact = workflowState.contacts[i];
      await fetch(`${API_BASE}/api/clients`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          company: workflowState.company,
          address: workflowState.address,
          postcode: workflowState.postcode,
          contactName: contact.name,
          jobTitle: contact.jobTitle,
          email: contact.email,
          phone: contact.phone,
        }),
      });
    }

    showToast(`Client added with ${workflowState.contacts.length} contact${workflowState.contacts.length !== 1 ? 's' : ''}`);
    document.getElementById('addClientWorkflow').classList.remove('visible');
    await loadClients();
  } catch (e) {
    showToast('Error: ' + e.message);
  }
}

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const tabBtn = document.querySelector(`[data-tab="${tab}"]`);
  if (tabBtn) tabBtn.classList.add('active');

  document.getElementById('candidatesView').classList.remove('visible');
  document.getElementById('clientsView').classList.remove('visible');

  if (tab === 'candidates') {
    document.getElementById('candidatesView').classList.add('visible');
    renderBoard();
  } else {
    document.getElementById('clientsView').classList.add('visible');
    renderClientsView();
  }
}

function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
