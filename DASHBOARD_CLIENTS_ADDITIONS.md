# Dashboard Clients Tab - HTML/CSS/JS Additions

## CSS to add (in the <style> section, before the closing </style>):

```css
  /* ---- Tabs ---- */
  #tabs{
    display:flex;gap:0;border-bottom:1px solid var(--border);background:var(--white);padding:0 24px;
  }
  .tab-btn{
    padding:14px 0;margin:0 20px;font-size:13.5px;color:#999;border:none;background:none;
    cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;font-family:inherit;
  }
  .tab-btn.active{color:var(--dark);border-bottom-color:var(--gold);font-weight:500;}
  .tab-btn:hover{color:var(--dark);}

  /* ---- Clients View ---- */
  #candidatesView{flex:1;display:flex;flex-direction:column;}
  #clientsView{display:none;flex:1;flex-direction:column;}
  #clientsView.visible{display:flex;}
  #clientsHeader{
    padding:16px 24px 14px;display:flex;justify-content:space-between;align-items:center;
    border-bottom:1px solid var(--border);
  }
  #clientsHeader h2{font-size:16px;color:var(--dark);font-weight:normal;}
  #addClientBtn{
    padding:9px 18px;background:var(--dark);color:var(--white);border:none;
    border-radius:2px;font-size:13.5px;cursor:pointer;font-family:inherit;
  }
  #addClientBtn:hover{background:#2c2c2c;}
  #clientsGrid{
    flex:1;overflow-y:auto;padding:18px 24px;display:grid;
    grid-template-columns:repeat(auto-fill, minmax(300px, 1fr));gap:18px;
  }
  .client-card{
    background:var(--white);border:1px solid var(--border);border-radius:2px;
    padding:18px;cursor:pointer;transition:all .15s;
  }
  .client-card:hover{border-color:var(--gold);box-shadow:0 2px 6px rgba(0,0,0,.08);}
  .client-card h3{font-size:15px;color:var(--dark);font-weight:500;margin-bottom:12px;}
  .client-card .detail{font-size:12.5px;color:#999;margin-bottom:10px;line-height:1.5;}
  .client-card .detail span{color:var(--dark);display:block;font-size:13px;font-weight:500;margin-bottom:4px;}
  .client-card .detail a{color:var(--gold);text-decoration:none;}
  .client-card .detail a:hover{text-decoration:underline;}
  .client-card .contact-badge{
    display:inline-block;background:var(--lightbg);padding:6px 10px;border-radius:2px;
    font-size:11.5px;color:var(--grey);margin-top:12px;
  }
  #noClients{
    text-align:center;padding:60px 24px;color:#bbb;font-size:14px;grid-column:1/-1;
  }
```

## HTML Structure Changes:

### 1. Replace the topbar section with this (add tabs above existing topbar):

```html
  <div id="main">
    <div id="tabs">
      <button class="tab-btn active" data-tab="candidates" onclick="switchTab('candidates')">Candidates</button>
      <button class="tab-btn" data-tab="clients" onclick="switchTab('clients')">Clients</button>
    </div>
    
    <div id="candidatesView" class="visible">
      <!-- existing topbar goes here -->
      <div id="topbar">
        ... existing topbar content ...
      </div>
      <!-- existing board goes here -->
      <div id="board">
        ... existing board content ...
      </div>
    </div>

    <div id="clientsView">
      <div id="clientsHeader">
        <h2>Client Accounts</h2>
        <button id="addClientBtn" onclick="openAddClientModal()">Add Client</button>
      </div>
      <div id="clientsGrid"></div>
    </div>
  </div>
```

### 2. Add this modal before the closing body tag (after existing modals):

```html
  <!-- Add Client Modal -->
  <div id="addClientOverlay" class="modal-overlay">
    <div class="modal">
      <button class="modal-close" onclick="closeModal('addClientOverlay')">×</button>
      <h2>Add New Client</h2>
      <p style="font-size:12.5px;color:#999;margin-bottom:18px;">Enter company and contact details</p>
      
      <form id="addClientForm" onsubmit="saveNewClient(); return false;">
        <div class="simple-form">
          <label>Company name *</label>
          <input type="text" id="clientCompany" required>
          
          <label>Address</label>
          <input type="text" id="clientAddress">
          
          <label>Postcode</label>
          <input type="text" id="clientPostcode">
          
          <label>Contact name</label>
          <input type="text" id="clientContactName">
          
          <label>Job title</label>
          <input type="text" id="clientJobTitle">
          
          <label>Email *</label>
          <input type="email" id="clientEmail" required>
          
          <label>Phone</label>
          <input type="tel" id="clientPhone">
          
          <div class="actions">
            <button type="submit" class="save">Add Client</button>
            <button type="button" class="cancel" onclick="closeModal('addClientOverlay')">Cancel</button>
          </div>
        </div>
      </form>
    </div>
  </div>
```

### 3. Add script include before closing body tag:

```html
  <script src="clients-update.js"></script>
  
  <script>
    // Initialize clients on load
    document.addEventListener('DOMContentLoaded', () => {
      loadClients();
    });
  </script>
```

## How it works:

1. **Tabs** at top let user switch between Candidates (existing) and Clients (new)
2. **Clients view** shows a grid of client company cards
3. **Add Client button** opens a modal form
4. Form submission POSTs to `/api/clients` endpoint
5. Client data is fetched from the sheet and displayed immediately
6. All data persists in the Google Sheet

## Files included:

- `clients-update.js` - Client-side JS functions
- Backend is already in `server.js` with `/api/clients` endpoints
