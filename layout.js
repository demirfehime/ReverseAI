/* Workbench layout preferences; narrow screens use a dismissible Copilot. */
(() => {
  const narrow = matchMedia('(max-width:1000px)');
  let saved = {};
  try { saved = JSON.parse(localStorage.getItem('reverseai.layout') || '{}') || {}; } catch (_) {}
  let sidebarCollapsed = saved.sidebarCollapsed === true;
  let copilotCollapsed = saved.copilotCollapsed === true;
  let drawerOpen = false;
  let width = Number.isFinite(saved.width) ? Math.max(260, Math.min(600, saved.width)) : 330;
  const handle = document.createElement('div');
  handle.className = 'copilot-resize';
  handle.tabIndex = 0;
  handle.setAttribute('role', 'separator');
  handle.setAttribute('aria-orientation', 'vertical');
  handle.setAttribute('aria-label', '调整 Copilot 宽度');
  handle.setAttribute('aria-valuemin', '260');
  handle.setAttribute('aria-valuemax', '600');
  $('.copilot').prepend(handle);
  function apply() {
    document.body.classList.toggle('sidebar-collapsed', sidebarCollapsed);
    document.body.classList.toggle('copilot-collapsed', copilotCollapsed);
    document.body.classList.toggle('copilot-open', narrow.matches && drawerOpen);
    document.body.style.setProperty('--copilot-width', copilotCollapsed ? '0px' : `${width}px`);
    handle.setAttribute('aria-valuenow', String(width));
    $('#toggleSidebar').setAttribute('aria-expanded', String(!sidebarCollapsed));
    $('#toggleCopilot').setAttribute('aria-expanded', String(narrow.matches ? drawerOpen : !copilotCollapsed));
    try { localStorage.setItem('reverseai.layout', JSON.stringify({sidebarCollapsed, copilotCollapsed, width})); } catch (_) {}
  }
  $('#toggleSidebar').onclick = () => { sidebarCollapsed = !sidebarCollapsed; apply(); };
  $('#toggleCopilot').onclick = () => {
    if (narrow.matches) drawerOpen = !drawerOpen;
    else copilotCollapsed = !copilotCollapsed;
    apply();
  };
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && drawerOpen) { drawerOpen = false; apply(); $('#toggleCopilot').focus(); }
  });
  narrow.addEventListener('change', apply);
  let dragging = false;
  handle.onpointerdown = event => { dragging = true; handle.setPointerCapture(event.pointerId); event.preventDefault(); };
  handle.onpointermove = event => {
    if (!dragging) return;
    width = Math.max(260, Math.min(600, innerWidth - event.clientX));
    apply();
  };
  handle.onpointerup = handle.onpointercancel = () => { dragging = false; };
  handle.onkeydown = event => {
    if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    event.preventDefault();
    width = Math.max(260, Math.min(600, width + (event.key === 'ArrowLeft' ? 20 : -20)));
    apply();
  };
  $('#manualAgents').onclick = () => {
    if (!state.settings?.config.agents.enabled) return toast('请先在 Agent 设置中启用子 Agent');
    runAgents();
  };
  $$('.nav').forEach(button => button.title = button.textContent.trim());
  apply();
})();
