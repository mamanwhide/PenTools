"""
Improve 3D attack graph — take 2 (exact string matches from file read).
"""
import pathlib

P = pathlib.Path("/home/h3llo/Documents/Project/Vulnx/PenTools/web/templates/graph/project_graph.html")
src = P.read_text()

# ─────────────────────────────────────────────────────────────────────────
# 1. Add theme CSS + light-mode overrides before </style>
# ─────────────────────────────────────────────────────────────────────────
old_style_end = "@keyframes spin{to{transform:rotate(360deg)}}\n.spin{animation:spin .8s linear infinite}\n</style>"
new_style_end = """@keyframes spin{to{transform:rotate(360deg)}}
.spin{animation:spin .8s linear infinite}

/* ── Dark / Light mode vars ──────────────────────────────── */
:root{ --graph-bg:#080b14; --ui-bg:#0d0f18; --panel-bg:#0f1016; --border:#1c1e2e; --text-muted:#4b5563; --text-main:#e2e8f0; }
.theme-light{ --graph-bg:#f1f5f9; --ui-bg:#f8fafc; --panel-bg:#ffffff; --border:#e2e8f0; --text-muted:#9ca3af; --text-main:#111827; }

#graph-root            { background:var(--graph-bg); }
#top-bar               { background:var(--ui-bg); border-color:var(--border); }
#filter-sidebar        { background:var(--ui-bg); border-color:var(--border); }
#detail-panel          { background:var(--panel-bg); }
#graph-legend          { background:rgba(0,0,0,.45); }
.theme-light #graph-legend { background:rgba(248,250,252,.92); }
#graph-mount           { background:var(--graph-bg); }
#ctx-menu              { background:var(--panel-bg); border-color:var(--border); }
#ctx-menu button       { color:var(--text-muted); }
#ctx-menu button:hover { background:var(--border); color:var(--text-main); }
.stat-pill             { border-color:var(--border); color:var(--text-muted); }
.filter-label          { color:var(--text-muted); }
.filter-row .lbl       { color:var(--text-muted); }
.icon-btn              { border-color:var(--border); color:var(--text-muted); }
.icon-btn:hover        { color:var(--text-main); }
.mode-btn:not(.active) { color:var(--text-muted); }
.mode-pill             { border-color:var(--border); background:var(--ui-bg); }

/* theme toggle button */
#btn-theme { width:30px;height:30px;display:flex;align-items:center;justify-content:center;border-radius:8px;border:1px solid var(--border);background:transparent;cursor:pointer;color:var(--text-muted);transition:color .15s,border-color .15s; }
#btn-theme:hover{ color:var(--text-main); border-color:#374151; }
</style>"""
assert old_style_end in src, "style end not found"
src = src.replace(old_style_end, new_style_end, 1)

# ─────────────────────────────────────────────────────────────────────────
# 2. Fix initial Labels button to have active class (showLabels starts true)
# ─────────────────────────────────────────────────────────────────────────
old_labels_btn = '    <button class="icon-btn" id="btn-labels" title="Toggle labels" onclick="APP.toggleLabels()">'
new_labels_btn = '    <button class="icon-btn active" id="btn-labels" title="Toggle labels" onclick="APP.toggleLabels()">'
assert old_labels_btn in src, "labels btn not found"
src = src.replace(old_labels_btn, new_labels_btn, 1)

# ─────────────────────────────────────────────────────────────────────────
# 3. Add theme toggle button before the filter button
# ─────────────────────────────────────────────────────────────────────────
old_filter_btn = '    <button class="icon-btn" id="btn-filter" title="Filters" onclick="APP.toggleSidebar()">'
new_filter_btn = '''    <!-- dark / light theme toggle -->
    <button id="btn-theme" title="Toggle dark / light mode" onclick="APP.toggleTheme()">
      <svg id="icon-sun" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" style="display:none"><circle cx="12" cy="12" r="5"/><path stroke-linecap="round" d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      <svg id="icon-moon" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>
    </button>

    <button class="icon-btn" id="btn-filter" title="Filters" onclick="APP.toggleSidebar()">'''
assert old_filter_btn in src, "filter btn not found"
src = src.replace(old_filter_btn, new_filter_btn, 1)

# ─────────────────────────────────────────────────────────────────────────
# 4. Add graphTheme state variable
# ─────────────────────────────────────────────────────────────────────────
old_state = 'let mode="3d", fg2=null, fg3=null, rawData={nodes:[],links:[]};\nlet showLabels=true, showSidebar=false, selNode=null, searchQuery="";\nlet ws=null;'
new_state = 'let mode="3d", fg2=null, fg3=null, rawData={nodes:[],links:[]};\nlet showLabels=true, showSidebar=false, selNode=null, searchQuery="";\nlet ws=null, graphTheme="dark";'
assert old_state in src, "state not found"
src = src.replace(old_state, new_state, 1)

# ─────────────────────────────────────────────────────────────────────────
# 5. Add toggleTheme() to APP — insert after reload()
# ─────────────────────────────────────────────────────────────────────────
old_reload = '  reload(){ const ic=document.getElementById("reload-icon"); ic.classList.add("spin"); loadData().finally(()=>ic.classList.remove("spin")); },'
new_reload = '''  reload(){ const ic=document.getElementById("reload-icon"); ic.classList.add("spin"); loadData().finally(()=>ic.classList.remove("spin")); },

  toggleTheme(){
    graphTheme = graphTheme==="dark" ? "light" : "dark";
    const root=document.getElementById("graph-root");
    root.classList.toggle("theme-light", graphTheme==="light");
    document.getElementById("icon-sun").style.display  = graphTheme==="light" ? "block" : "none";
    document.getElementById("icon-moon").style.display = graphTheme==="dark"  ? "block" : "none";
    renderGraph();
  },'''
assert old_reload in src, "reload fn not found"
src = src.replace(old_reload, new_reload, 1)

# ─────────────────────────────────────────────────────────────────────────
# 6. Make renderGraph() use theme-aware bg
# ─────────────────────────────────────────────────────────────────────────
old_bg2 = '    fg2=ForceGraph()(mount)\n      .width(W).height(H)\n      .backgroundColor("#080b14")'
new_bg2 = '    fg2=ForceGraph()(mount)\n      .width(W).height(H)\n      .backgroundColor(graphTheme==="light"?"#f1f5f9":"#080b14")'
assert old_bg2 in src, "2d bg not found"
src = src.replace(old_bg2, new_bg2, 1)

old_bg3 = '    fg3=ForceGraph3D()(mount)\n      .width(W).height(H)\n      .backgroundColor("#080b14")'
new_bg3 = '    fg3=ForceGraph3D()(mount)\n      .width(W).height(H)\n      .backgroundColor(graphTheme==="light"?"#f1f5f9":"#080b14")'
assert old_bg3 in src, "3d bg not found"
src = src.replace(old_bg3, new_bg3, 1)

# ─────────────────────────────────────────────────────────────────────────
# 7. Update 2D link colors to adapt for light mode
# ─────────────────────────────────────────────────────────────────────────
old_link2d = '      .linkColor(l=>l.severity?(SEV_COLOR[l.severity]+"88"):"rgba(148,163,184,.3)")'
new_link2d = '      .linkColor(l=>l.severity?(SEV_COLOR[l.severity]+(graphTheme==="light"?"cc":"88")):(graphTheme==="light"?"rgba(100,116,139,.5)":"rgba(148,163,184,.3)"))'
assert old_link2d in src, "2d link color not found"
src = src.replace(old_link2d, new_link2d, 1)

old_link3d = '      .linkColor(l=>l.severity?(SEV_COLOR[l.severity]+"99"):"rgba(148,163,184,.4)")'
new_link3d = '      .linkColor(l=>l.severity?(SEV_COLOR[l.severity]+(graphTheme==="light"?"cc":"99")):(graphTheme==="light"?"rgba(100,116,139,.55)":"rgba(148,163,184,.4)"))'
assert old_link3d in src, "3d link color not found"
src = src.replace(old_link3d, new_link3d, 1)

# ─────────────────────────────────────────────────────────────────────────
# 8. Rewrite 2D nodeCanvasObject (find dynamically with unique key)
# ─────────────────────────────────────────────────────────────────────────
search_2d_start = '      .nodeCanvasObjectMode(()=>"after")\n      .nodeCanvasObject('
search_2d_end   = '      })'
if search_2d_start in src:
    s = src.index(search_2d_start)
    e = src.index(search_2d_end, s) + len(search_2d_end)
    actual_2d = src[s:e]
    print("Found 2D block (first 120 chars):", repr(actual_2d[:120]))
    new_2d_label = """      .nodeCanvasObjectMode(()=>"after")
      .nodeCanvasObject((n,ctx,sc)=>{
        const isLight=graphTheme==="light";
        const isSel=selNode&&selNode.id===n.id;
        const nodeCol=nColor(n);
        const r=nSize(n);
        const abbr=TYPE_ABBR[n.node_type]||"?";
        const fullName=n.label||n.value||"";
        const name=fullName.length>22?fullName.slice(0,20)+"\u2026":fullName;
        const fs=Math.max(10/sc,2.4);
        ctx.textAlign="center"; ctx.textBaseline="top";
        if(showLabels && name){
          // Pill background
          ctx.font="bold "+fs+"px monospace";
          const tw=ctx.measureText(name).width;
          const pad=fs*0.45, brd=1.2/sc;
          const bx=n.x-tw/2-pad, by=n.y+r+fs*0.3;
          const bw=tw+pad*2, bh=fs+pad*2, rad=bh/3;
          ctx.fillStyle=isLight?"rgba(255,255,255,0.92)":"rgba(8,11,20,0.88)";
          ctx.beginPath();
          ctx.moveTo(bx+rad,by); ctx.arcTo(bx+bw,by,bx+bw,by+bh,rad);
          ctx.arcTo(bx+bw,by+bh,bx,by+bh,rad); ctx.arcTo(bx,by+bh,bx,by,rad);
          ctx.arcTo(bx,by,bx+bw,by,rad); ctx.closePath(); ctx.fill();
          // Coloured border
          ctx.strokeStyle=nodeCol; ctx.lineWidth=brd; ctx.stroke();
          // Label text
          ctx.fillStyle=isSel?"#4ade80":isLight?"#111827":"#f1f5f9";
          ctx.fillText(name,n.x,by+pad);
          // Sub badge
          const sub=n.node_type==="finding"?(n.severity||"info").toUpperCase():abbr;
          const sfs=Math.max(fs*0.75,1.8);
          ctx.font="700 "+sfs+"px monospace";
          ctx.fillStyle=nodeCol; ctx.textBaseline="top";
          ctx.fillText(sub,n.x,by+bh+sfs*0.15);
        } else {
          // Minimal badge (labels off)
          const bsize=r*0.9;
          ctx.fillStyle=isLight?"rgba(255,255,255,0.9)":"rgba(8,11,20,0.82)";
          ctx.beginPath(); ctx.arc(n.x,n.y-r*0.65,bsize,0,Math.PI*2); ctx.fill();
          ctx.strokeStyle=nodeCol; ctx.lineWidth=1/sc; ctx.stroke();
          ctx.font="bold "+Math.max(8/sc,1.8)+"px monospace";
          ctx.fillStyle=nodeCol; ctx.textBaseline="middle";
          ctx.fillText(abbr,n.x,n.y-r*0.65);
        }
      })"""
    src = src.replace(actual_2d, new_2d_label, 1)
    print("2D label block replaced OK")
else:
    print("ERROR: 2D block start not found")

# ─────────────────────────────────────────────────────────────────────────
# 9. Replace 3D sprite label section (always-visible per node)
# ─────────────────────────────────────────────────────────────────────────
search_3d_key = "  // Sprite label\n  if(ST&&(showLabels||n.node_type===\"target\""
if search_3d_key in src:
    s3 = src.index(search_3d_key)
    # Find the matching "  return group;\n}" after it
    e3 = src.index("  return group;\n}", s3) + len("  return group;\n}")
    actual_3d = src[s3:e3]
    print("Found 3D label block (first 80 chars):", repr(actual_3d[:80]))
    new_3d_label = """  // ── Always-visible node labels (colour from node, never black) ─────────
  if(ST){
    const isLight=graphTheme==="light";
    const textMain=isSel?"#4ade80":isLight?"#111827":"#f1f5f9";
    const spriteBg=isLight?"rgba(255,255,255,0.88)":"rgba(6,8,18,0.84)";
    const fullName=n.label||n.value||"";
    const nm=fullName.length>24?fullName.slice(0,22)+"\u2026":fullName;

    // Main name label — shown when showLabels on
    if(showLabels && nm){
      const spMain=new ST(nm);
      spMain.color=textMain;
      spMain.textHeight=3;
      spMain.fontFace="monospace";
      spMain.fontWeight="600";
      spMain.backgroundColor=spriteBg;
      spMain.borderWidth=0.9;
      spMain.borderColor=col;
      spMain.borderRadius=3;
      spMain.padding=2;
      spMain.position.y=sz+9;
      group.add(spMain);
    }

    // Type / severity badge — ALWAYS visible so nodes are never unlabelled
    let sublabel="";
    if(n.node_type==="finding")         sublabel=(n.severity||"info").toUpperCase();
    else if(n.node_type==="module_run") sublabel="MOD";
    else if(n.node_type==="target")     sublabel=(n.target_type||"DOMAIN").toUpperCase().slice(0,8);
    else if(n.node_type==="project")    sublabel="PROJECT";

    if(sublabel){
      const spSub=new ST(sublabel);
      spSub.color=col;                  // node's own colour — readable on any bg
      spSub.textHeight=2;
      spSub.fontFace="monospace";
      spSub.fontWeight="700";
      spSub.backgroundColor="rgba(0,0,0,0)";
      spSub.padding=0.5;
      spSub.position.y=sz+4;
      group.add(spSub);
    }
  }
  return group;
}"""
    src = src.replace(actual_3d, new_3d_label, 1)
    print("3D label block replaced OK")
else:
    print("ERROR: 3D label block not found")

# ─────────────────────────────────────────────────────────────────────────
# Write and verify
# ─────────────────────────────────────────────────────────────────────────
P.write_text(src)
result = P.read_text()
checks = {
    "no injections":      "<---" not in result,
    "theme-light CSS":    ".theme-light" in result,
    "toggleTheme fn":     "toggleTheme" in result,
    "theme btn HTML":     "btn-theme" in result,
    "sun icon":           "icon-sun" in result,
    "moon icon":          "icon-moon" in result,
    "graphTheme state":   'graphTheme="dark"' in result,
    "spriteBg 3d":        "spriteBg" in result,
    "borderColor=col":    "borderColor=col" in result,
    "isLight text":       '"#111827"' in result,
    "labels btn active":  'class="icon-btn active" id="btn-labels"' in result,
    "theme bg 2d":        'graphTheme==="light"?"#f1f5f9":"#080b14"' in result,
    "sublabel 3d":        "sublabel" in result,
    "2d light pill":      "rgba(255,255,255,0.92)" in result,
    "3d always visible":  "Always visible" in result,
    "ends correctly":     result.rstrip().endswith("{% endblock %}"),
}
print(f"\nLines: {result.count(chr(10))}")
for k, v in checks.items():
    print(f"  {'OK' if v else 'FAIL'} {k}")
