// Add this route to the existing l2h-api.onrender.com service (same file/pattern as /api/candidates)
// Requires the same googleapis "sheets" client and SHEET_ID already configured for the dashboard

app.post('/api/applications/transport-coordinator', async (req, res) => {
  try {
    const {
      name,
      email,
      phone,
      employmentStatus,
      noticePeriod,
      transportBackground,
      recentRole,
      liaisonHauliers,
      kpiComfort,
      excelSkill,
      priorityRating,
      workEnvironment,
      location,
      commute,
      salaryExpectation,
      additionalInfo
    } = req.body;

    if (!name || !email || !phone) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const applicationId = `tc-${Date.now()}`;
    const dateApplied = new Date().toISOString();
    const locationCombined = `${location} (Commute: ${commute})`;

    // Column order must match the "Applications - Transport Coordinator" tab headers exactly:
    // Application ID | Date Applied | Candidate Name | Email | Phone | Current Employment Status |
    // Notice Period | Transport Background | Recent Role Description | Customer/Haulier Liaison |
    // KPI/OTIF Comfort | Excel Skill Level | Multi-priority Rating | Ideal Work Environment |
    // Location/Trentham Commute | Salary Expectation | Additional Info | Company | Contact/Hiring Manager | Status

    const row = [
      applicationId,
      dateApplied,
      name,
      email,
      phone,
      employmentStatus,
      noticePeriod,
      transportBackground,
      recentRole,
      liaisonHauliers,
      kpiComfort,
      excelSkill,
      priorityRating,
      workEnvironment,
      locationCombined,
      salaryExpectation,
      additionalInfo || '',
      '',        // Company - left blank, assigned by Ella in dashboard
      '',        // Contact/Hiring Manager - left blank, assigned by Ella in dashboard
      'applied'  // Status - lowercase to match existing dashboard convention
    ];

    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: "'Applications - Transport Coordinator'!A:T",
      valueInputOption: 'USER_ENTERED',
      requestBody: { values: [row] }
    });

    res.json({ success: true, applicationId });

  } catch (err) {
    console.error('Application submission error:', err);
    res.status(500).json({ error: 'Failed to save application' });
  }
});

// CORS note: if the apply form is served from careers.live2helprecruitment.co.uk and this
// endpoint is on l2h-api.onrender.com, confirm CORS already allows that origin (it should,
// since the dashboard already calls this Render service from the same domain). If it doesn't,
// add careers.live2helprecruitment.co.uk to the allowed origins list alongside the dashboard.
