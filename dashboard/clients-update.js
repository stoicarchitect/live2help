// Client management functions

let CLIENTS = [];
let currentTab = 'candidates';

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
  
  if (CLIENTS.length === 0) {
    grid.innerHTML = '<div id="noClients">No clients yet. Click "Add Client" to get started.</div>';
    return;
  }

  grid.innerHTML = CLIENTS.map(client => `
    <div class="client-card">
      <h3>${escapeHtml(client.company)}</h3>
      <div class="detail">
        <span>${escapeHtml(client.address)}</span>
        ${client.postcode ? escapeHtml(client.postcode) : 'No postcode'}
      </div>
      <div class="detail">
        <strong>${escapeHtml(client.contactName)}</strong><br/>
        ${escapeHtml(client.jobTitle)}
      </div>
      <div class="detail">
        <a href="mailto:${escapeHtml(client.email)}">${escapeHtml(client.email)}</a><br/>
        <a href="tel:${escapeHtml(client.phone)}">${escapeHtml(client.phone)}</a>
      </div>
      <div class="contact-badge">Added: ${new Date(client.timestamp).toLocaleDateString()}</div>
    </div>
  `).join('');
}

function openAddClientModal() {
  document.getElementById('addClientForm').reset();
  document.getElementById('addClientOverlay').classList.add('visible');
}

async function saveNewClient() {
  const company = document.getElementById('clientCompany').value.trim();
  const address = document.getElementById('clientAddress').value.trim();
  const postcode = document.getElementById('clientPostcode').value.trim();
  const contactName = document.getElementById('clientContactName').value.trim();
  const jobTitle = document.getElementById('clientJobTitle').value.trim();
  const email = document.getElementById('clientEmail').value.trim();
  const phone = document.getElementById('clientPhone').value.trim();

  if (!company || !email) {
    showToast('Company and email are required');
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/clients`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        company,
        address,
        postcode,
        contactName,
        jobTitle,
        email,
        phone,
      }),
    });

    if (res.ok) {
      showToast('Client added successfully');
      document.getElementById('addClientOverlay').classList.remove('visible');
      await loadClients();
    } else {
      const err = await res.json();
      showToast('Error: ' + (err.error || 'Failed to add client'));
    }
  } catch (e) {
    showToast('Error: ' + e.message);
  }
}

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`[data-tab="${tab}"]`).classList.add('active');

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
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
