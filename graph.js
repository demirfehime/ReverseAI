/* Rectangle-boundary routing. Only real obstacles introduce bends. */
(function(root){
  const W=220,H=120,PAD=16;
  function intersects(a,b,r){
    let lo=0,hi=1;
    for(const [v,d,min,max] of [[a.x,b.x-a.x,r.x+.01,r.x+r.w-.01],[a.y,b.y-a.y,r.y+.01,r.y+r.h-.01]]){
      if(Math.abs(d)<1e-8){if(v<min||v>max)return false;continue}
      const t1=(min-v)/d,t2=(max-v)/d;lo=Math.max(lo,Math.min(t1,t2));hi=Math.min(hi,Math.max(t1,t2));if(lo>hi)return false;
    }
    return hi>=0&&lo<=1;
  }
  const distance=(a,b)=>Math.hypot(a.x-b.x,a.y-b.y);
  function rounded(points){
    let d=`M${points[0].x},${points[0].y}`;
    for(let i=1;i<points.length-1;i++){
      const a=points[i-1],b=points[i],c=points[i+1],r=Math.min(12,distance(a,b)/3,distance(b,c)/3);
      const u={x:b.x+(a.x-b.x)*r/distance(a,b),y:b.y+(a.y-b.y)*r/distance(a,b)},v={x:b.x+(c.x-b.x)*r/distance(b,c),y:b.y+(c.y-b.y)*r/distance(b,c)};
      d+=` L${u.x},${u.y} Q${b.x},${b.y} ${v.x},${v.y}`;
    }
    const end=points.at(-1);return d+` L${end.x},${end.y}`;
  }
  function route(a,b,others=[]){
    if(Math.abs(a.x-b.x)<W&&Math.abs(a.y-b.y)<H)return {path:'',points:[],overlap:true};
    const ac={x:a.x+W/2,y:a.y+H/2},bc={x:b.x+W/2,y:b.y+H/2},dx=bc.x-ac.x,dy=bc.y-ac.y;
    const t=1/Math.max(Math.abs(dx)/(W/2),Math.abs(dy)/(H/2));
    const start={x:ac.x+dx*t,y:ac.y+dy*t},end={x:bc.x-dx*t,y:bc.y-dy*t};
    const rects=others.map(p=>({x:p.x-PAD,y:p.y-PAD,w:W+PAD*2,h:H+PAD*2}));
    const clear=(u,v)=>!rects.some(r=>intersects(u,v,r));
    if(clear(start,end))return {path:`M${start.x},${start.y} L${end.x},${end.y}`,points:[start,end]};
    // Visibility graph over obstacle corners finds the shortest local detour.
    const points=[start,end,...rects.flatMap(r=>[{x:r.x,y:r.y},{x:r.x+r.w,y:r.y},{x:r.x+r.w,y:r.y+r.h},{x:r.x,y:r.y+r.h}])];
    const costs=points.map(()=>Infinity),previous=[],visited=new Set();costs[0]=0;
    for(let step=0;step<points.length;step++){
      let u=-1;for(let i=0;i<points.length;i++)if(!visited.has(i)&&(u<0||costs[i]<costs[u]))u=i;
      if(u<0||!Number.isFinite(costs[u])||u===1)break;visited.add(u);
      for(let v=0;v<points.length;v++)if(!visited.has(v)&&clear(points[u],points[v])){const candidate=costs[u]+distance(points[u],points[v]);if(candidate<costs[v]){costs[v]=candidate;previous[v]=u}}
    }
    if(!Number.isFinite(costs[1]))return {path:'',points:[],overlap:true};
    const chain=[];for(let i=1;i!==undefined;i=previous[i])chain.unshift(points[i]);
    return {path:rounded(chain),points:chain};
  }
  root.EvidenceRouting={route,intersects};
  if(typeof module!=='undefined')module.exports=root.EvidenceRouting;
})(typeof globalThis!=='undefined'?globalThis:this);
