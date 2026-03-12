const canvas = new fabric.Canvas("image-canvas", {
  enableRetinaScaling: true
});
function requestCanvasZoomRecalc() {
  if (typeof window.recalculateCanvasZoom !== "function") return;
  requestAnimationFrame(() => {
    window.recalculateCanvasZoom();
    setTimeout(() => window.recalculateCanvasZoom(), 80);
    setTimeout(() => window.recalculateCanvasZoom(), 180);
  });
}


const appState = {
  outerMargin: 0,
  innerPadding: 10,
  innerWidth: 400,
  innerHeight: 400,
  selectedWidth: 400,
  selectedHeight: 400,
  uploadedImage: null,
  scaleFactor: 1,
  angle: 0,
  zoom: 1.0,     
  minZoom: 0.1,    
  maxZoom: 3.0,     
  clipPath: null,
  outerFrame: null,
  innerCanvas: null,
  borderSize: 0.75,
  borderColor: "#000000",
  canvasBgColor: "#ffffff",
  canvasBorderColor: "#00000060",
  canvasWidth: 0,
  canvasHeight: 0,
  newCanvasWidth: 0,
  newCanvasHeight: 0,
  imageWidth: 0,
  imageHeight: 0,
  newimageleft: 0,
  newimagetop: 0,
  border: 0,
  baseEdgeType: "FitToEdge",
  selectedEdgeType: "FitToEdge",
  isMirrorMode: false,
  cropState: {
    isCropped: false,
    backup: null,
    isSelecting: false,
    selectionRect: null
  }
  
};

const MIRROR_MODE_STORAGE_KEY = "p2pMirrorMode";

function getCanvasFrontFaceBounds() {
  const edgeSize = Number(appState.innerPadding ?? appState.borderSize ?? 0);
  const canvasWidth = typeof canvas.getWidth === "function" ? canvas.getWidth() : canvas?.width;
  const canvasHeight = typeof canvas.getHeight === "function" ? canvas.getHeight() : canvas?.height;

  if (!Number.isFinite(canvasWidth) || !Number.isFinite(canvasHeight)) {
    return null;
  }

  const width = canvasWidth - edgeSize * 2;
  const height = canvasHeight - edgeSize * 2;
  if (width <= 0 || height <= 0) {
    return null;
  }

  return {
    left: edgeSize,
    top: edgeSize,
    width,
    height,
    edgeSize
  };
}

function getEffectiveEdgeType() {
  if (appState.isMirrorMode) {
    return "MirrorWrap";
  }

  return appState.baseEdgeType || appState.selectedEdgeType || "FitToEdge";
}

function syncSelectedEdgeType() {
  const effectiveEdgeType = getEffectiveEdgeType();
  const hiddenFormInput = document.getElementById("final-image-type-data");

  appState.selectedEdgeType = effectiveEdgeType;

  if (hiddenFormInput) {
    hiddenFormInput.value = effectiveEdgeType;
  }
}

function syncMirrorModeUI() {
  const mirrorToggleBtn = document.getElementById("mirror-mode-toggle");
  const mirrorInput = document.getElementById("mirror-mode-data");
  const isActive = Boolean(appState.isMirrorMode);

  if (mirrorToggleBtn) {
    mirrorToggleBtn.classList.toggle("is-active", isActive);
    mirrorToggleBtn.setAttribute("aria-pressed", String(isActive));
    mirrorToggleBtn.textContent = isActive ? "Mirror edges on" : "Mirror edges off";
  }

  if (mirrorInput) {
    mirrorInput.value = isActive ? "true" : "false";
  }
}

function setMirrorMode(enabled, options = {}) {
  const nextValue = Boolean(enabled);
  const shouldPersist = options.persist !== false;

  appState.isMirrorMode = nextValue;

  if (shouldPersist) {
    try {
      sessionStorage.setItem(MIRROR_MODE_STORAGE_KEY, nextValue ? "true" : "false");
    } catch (error) {
      console.warn("Unable to persist mirror mode:", error);
    }
  }

  syncSelectedEdgeType();
  syncMirrorModeUI();

  if (typeof window.drawBorderOnTop === "function") {
    window.drawBorderOnTop();
  }
  canvas.requestRenderAll();
}

function initMirrorModeToggle() {
  const mirrorToggleBtn = document.getElementById("mirror-mode-toggle");
  if (!mirrorToggleBtn) return;

  if (!mirrorToggleBtn.dataset.boundMirrorToggle) {
    mirrorToggleBtn.addEventListener("click", () => {
      setMirrorMode(!appState.isMirrorMode);
    });
    mirrorToggleBtn.dataset.boundMirrorToggle = "true";
  }

  let storedValue = null;
  try {
    storedValue = sessionStorage.getItem(MIRROR_MODE_STORAGE_KEY);
  } catch (error) {
    console.warn("Unable to read mirror mode state:", error);
  }

  setMirrorMode(storedValue === "true", { persist: false });
}

function createFrontFaceSnapshotCanvas(targetWidth, targetHeight) {
  const bounds = getCanvasFrontFaceBounds();
  const sourceCanvas = canvas?.lowerCanvasEl;

  if (!bounds || !sourceCanvas) {
    return null;
  }

  const faceCanvas = document.createElement("canvas");
  faceCanvas.width = Math.max(1, Math.round(targetWidth ?? bounds.width));
  faceCanvas.height = Math.max(1, Math.round(targetHeight ?? bounds.height));

  const faceCtx = faceCanvas.getContext("2d");
  if (!faceCtx) {
    return null;
  }

  faceCtx.imageSmoothingEnabled = true;
  faceCtx.drawImage(
    sourceCanvas,
    bounds.left,
    bounds.top,
    bounds.width,
    bounds.height,
    0,
    0,
    faceCanvas.width,
    faceCanvas.height
  );

  return faceCanvas;
}

function loadImageFromAnySource(source) {
  return new Promise((resolve, reject) => {
    if (source instanceof HTMLImageElement) {
      if (source.complete && source.naturalHeight !== 0) {
        resolve(source);
        return;
      }

      source.onload = () => resolve(source);
      source.onerror = () => reject(new Error("Failed to load image element"));
      return;
    }

    if (source instanceof HTMLCanvasElement) {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error("Failed to load canvas image"));
      img.src = source.toDataURL();
      return;
    }

    if (source instanceof File || source instanceof Blob) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const img = new Image();
        img.onload = () => resolve(img);
        img.onerror = () => reject(new Error("Failed to load file/blob image"));
        img.src = event.target.result;
      };
      reader.onerror = () => reject(new Error("Failed to read file"));
      reader.readAsDataURL(source);
      return;
    }

    const resolvedSource = typeof source === "string"
      ? source
      : source?.src || source?.url || source?.imageUrl || source?.data || source?.image || source?.link;

    if (!resolvedSource) {
      reject(new Error(`Unsupported image source type: ${typeof source}`));
      return;
    }

    const img = new Image();
    if (!resolvedSource.startsWith("data:") && !resolvedSource.startsWith("blob:")) {
      img.crossOrigin = "anonymous";
    }
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("Failed to load image source"));
    img.src = resolvedSource;
  });
}

function drawMirroredEdgeStrips(ctx, faceCanvas, edgeSize, destX = 0, destY = 0, drawCenter = false) {
  if (!ctx || !faceCanvas) return;

  const faceWidth = faceCanvas.width;
  const faceHeight = faceCanvas.height;
  const edge = Math.max(1, Math.round(edgeSize));
  const horizontalSample = Math.max(1, Math.min(edge, faceHeight));
  const verticalSample = Math.max(1, Math.min(edge, faceWidth));

  if (drawCenter) {
    ctx.drawImage(faceCanvas, destX + edge, destY + edge, faceWidth, faceHeight);
  }

  ctx.save();
  ctx.translate(destX + edge, destY + edge);
  ctx.scale(1, -1);
  ctx.drawImage(faceCanvas, 0, 0, faceWidth, horizontalSample, 0, 0, faceWidth, edge);
  ctx.restore();

  ctx.save();
  ctx.translate(destX + edge, destY + faceHeight + edge * 2);
  ctx.scale(1, -1);
  ctx.drawImage(
    faceCanvas,
    0,
    Math.max(0, faceHeight - horizontalSample),
    faceWidth,
    horizontalSample,
    0,
    0,
    faceWidth,
    edge
  );
  ctx.restore();

  ctx.save();
  ctx.translate(destX + edge, destY + edge);
  ctx.scale(-1, 1);
  ctx.drawImage(faceCanvas, 0, 0, verticalSample, faceHeight, 0, 0, edge, faceHeight);
  ctx.restore();

  ctx.save();
  ctx.translate(destX + faceWidth + edge * 2, destY + edge);
  ctx.scale(-1, 1);
  ctx.drawImage(
    faceCanvas,
    Math.max(0, faceWidth - verticalSample),
    0,
    verticalSample,
    faceHeight,
    0,
    0,
    edge,
    faceHeight
  );
  ctx.restore();

  const cornerSampleSize = Math.max(1, Math.min(edge, faceWidth, faceHeight));
  const cornerConfigs = [
    { dx: destX + edge, dy: destY + edge, sx: 0, sy: 0 },
    {
      dx: destX + faceWidth + edge * 2,
      dy: destY + edge,
      sx: Math.max(0, faceWidth - cornerSampleSize),
      sy: 0
    },
    {
      dx: destX + edge,
      dy: destY + faceHeight + edge * 2,
      sx: 0,
      sy: Math.max(0, faceHeight - cornerSampleSize)
    },
    {
      dx: destX + faceWidth + edge * 2,
      dy: destY + faceHeight + edge * 2,
      sx: Math.max(0, faceWidth - cornerSampleSize),
      sy: Math.max(0, faceHeight - cornerSampleSize)
    }
  ];

  cornerConfigs.forEach(({ dx, dy, sx, sy }) => {
    ctx.save();
    ctx.translate(dx, dy);
    ctx.scale(-1, -1);
    ctx.drawImage(faceCanvas, sx, sy, cornerSampleSize, cornerSampleSize, 0, 0, edge, edge);
    ctx.restore();
  });
}

function drawMirrorPreviewOnTop(ctx, edgeSize) {
  if (!appState.isMirrorMode || !appState.uploadedImage || !Number.isFinite(edgeSize) || edgeSize <= 0) {
    return false;
  }

  const bounds = getCanvasFrontFaceBounds();
  if (!bounds) {
    return false;
  }

  const faceCanvas = createFrontFaceSnapshotCanvas(bounds.width, bounds.height);
  if (!faceCanvas) {
    return false;
  }

  ctx.save();
  drawMirroredEdgeStrips(ctx, faceCanvas, edgeSize, 0, 0, false);
  ctx.restore();

  return true;
}
// ============================
// CENTER GUIDELINES WITH SNAPPING
// ============================
let vCenterLine, hCenterLine;
const THRESHOLD = 10; // 4px threshold for snapping

// Function to create center lines (always visible)
function createCenterLines() {
  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;
  
  // Remove existing lines if any
  if (vCenterLine) canvas.remove(vCenterLine);
  if (hCenterLine) canvas.remove(hCenterLine);
  
  // Create vertical center line
  vCenterLine = new fabric.Line(
    [centerX, 0, centerX, canvas.height], 
    {
      stroke: 'red',
      strokeWidth: 1,
      selectable: false,
      evented: false,
      opacity: 0.3, // Semi-transparent
      name: 'centerLine',
      strokeDashArray: [5, 5] // Dashed line for better visibility
    }
  );
  
  // Create horizontal center line
  hCenterLine = new fabric.Line(
    [0, centerY, canvas.width, centerY], 
    {
      stroke: 'red',
      strokeWidth: 1,
      selectable: false,
      evented: false,
      opacity: 0.3, // Semi-transparent
      name: 'centerLine',
      strokeDashArray: [5, 5] // Dashed line for better visibility
    }
  );
  
  canvas.add(vCenterLine);
  canvas.add(hCenterLine);
  bringCenterLinesToFront();
  canvas.requestRenderAll();
}

// Function to update center lines position
function updateCenterLines() {
  if (!vCenterLine || !hCenterLine) {
    createCenterLines();
    return;
  }
  
  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;
  
  vCenterLine.set({
    x1: centerX,
    y1: 0,
    x2: centerX,
    y2: canvas.height
  });
  
  hCenterLine.set({
    x1: 0,
    y1: centerY,
    x2: canvas.width,
    y2: centerY
  });
  
  bringCenterLinesToFront();
  canvas.requestRenderAll();
}


const mockupPlacements = [
  { x: 0.3545, y: 0.199, w: 0.295, h: 0.375 }, 
  { x: 0.382, y: 0.354, w: 0.23, h: 0.292 }, 
  { x: 0.373, y: 0.106, w: 0.104, h: 0.132 }, 
  { x: 0.376, y: 0.488, w: 0.246, h: 0.311 }, 
];

const mockupState = {
  croppedWidth: 0,
  croppedHeight: 0
};

document.addEventListener("DOMContentLoaded", initWrapSelector);
window.addEventListener("load", initWrapSelector);
document.addEventListener("DOMContentLoaded", initMirrorModeToggle);
window.addEventListener("load", initMirrorModeToggle);
function initWrapSelector() {

  const options = document.querySelectorAll('.wrap-option');
  const controls = document.querySelector('.controls');

  if (!options.length) {
    retryInit();
    return;
  }

  const appState = {
    selectedWrap: "fit",
    selectedEdgeType: "FitToEdge"
  };

  /* ---------------- Controls ---------------- */
  function updateControlsDisplay(value) {
    if (!controls) return;

    if (value === "white" || value === "black") {
      controls.style.display = "flex";
    } else {
      controls.style.display = "flex";
    }
  }

  /* ---------------- Initial Selection ---------------- */
  function applyInitialSelection() {

    let value =
      sessionStorage.getItem("selectedWrap") ||
      document.querySelector('.wrap-option input:checked')?.value ||
      "fit";


    const input = document.querySelector(
      `.wrap-option input[value="${value}"]`
    );

    if (!input) return false;

    const parent = input.closest('.wrap-option');
    if (!parent || parent.classList.contains('disabled')) return false;

    options.forEach(o => o.classList.remove('active'));
    parent.classList.add('active');

    input.checked = true;

    appState.selectedWrap = value;
    sessionStorage.setItem("selectedWrap", value);

    updateControlsDisplay(value);
    applyWrapEffects(value);

    return true;
  }

  /* ---------------- Click Handling ---------------- */
  options.forEach(opt => {
    opt.addEventListener('click', e => {
      if (opt.classList.contains('disabled')) return;
      e.preventDefault();

      options.forEach(o => {
        o.classList.remove('active');
        const i = o.querySelector('input');
        if (i) i.checked = false;
      });

      opt.classList.add('active');
      const input = opt.querySelector('input');
      if (!input) return;

      input.checked = true;
      input.dispatchEvent(new Event('change', { bubbles: true }));

      const value = input.value;

      appState.selectedWrap = value;
      sessionStorage.setItem("selectedWrap", value);

      updateControlsDisplay(value);
      applyWrapEffects(value);
    });
  });

  /* ---------------- Wrap Effects ---------------- */
  function applyWrapEffects(value) {
    if (!value) value = sessionStorage.getItem("selectedWrap");
    if (!value) return;

    if (value === "black") {
      window.appState.baseEdgeType = "BlackWrap";
      syncSelectedEdgeType();
      coverFrame("black");
    }

    else if (value === "white") {
      window.appState.baseEdgeType = "WhiteWrap";
      syncSelectedEdgeType();
      coverFrame("white");
    }

    else {
      window.appState.baseEdgeType = "FitToEdge";
      syncSelectedEdgeType();
      // fitImageToFrame(true);
     FitFrontFrame();
    }
  }

  /* ---------------- Init ---------------- */
  applyInitialSelection();

  function retryInit() {
    setTimeout(initWrapSelector, 300);
  }
}

const uploadInput = document.getElementById("upload-image");
const uploadInputwrap = document.querySelector(".upload-wrapper");
const galleryWrapper = document.getElementById("galleryWrapper");
const customForm = document.getElementById("custom-image-form");

canvas.on("object:scaling", function() {
  updateMovementConstraints();
  updatePositionInfo();
});

canvas.on("object:rotating", function() {
  updateMovementConstraints();
  updatePositionInfo();
});

document.querySelectorAll(".image-conform-btn").forEach(div => {
  div.style.pointerEvents = "none";
  div.style.opacity = "0.5";
});

function getImagePosition() {
  if (!appState.uploadedImage) return null;

  const img = appState.uploadedImage;
  const left = img.left - img.getScaledWidth() / 2;
  const top = img.top - img.getScaledHeight() / 2;
  const right = left + img.getScaledWidth();
  const bottom = top + img.getScaledHeight();

  return {
    left: left,
    top: top,
    right: right,
    bottom: bottom,
    width: img.getScaledWidth(),
    height: img.getScaledHeight(),
    scale: (img.scaleX * 100) / 100,
    angle: img.angle,
  };
}

// Add movement constraint functions
function setMovementConstraints() {
  if (!appState.uploadedImage) return;
  
  const img = appState.uploadedImage;
  const width = img.getScaledWidth();
  const height = img.getScaledHeight();
  const isLandscape = width > height;
  const isPortrait = height > width;
  const isSquare = width === height;
  
  img.setCoords();
  canvas.requestRenderAll();
}

function updateMovementConstraints() {
  if (!appState.uploadedImage) return;
  
  const img = appState.uploadedImage;
  const width = img.getScaledWidth();
  const height = img.getScaledHeight(); 
  
  img.setCoords();
}

document.addEventListener("DOMContentLoaded", function () {
  const boostBtn = document.querySelector(".boost-img-btn");
  const conformBtn = document.querySelector(".image-conform-btn");

  if (!boostBtn || !conformBtn) return; 

  function updateDisplay() {
    const boostDisplay = window.getComputedStyle(boostBtn).display;

    if (boostDisplay === "none") {
      conformBtn.style.display = "flex";
    } else if (boostDisplay === "flex") {
      conformBtn.style.display = "none";
    }
  }
  updateDisplay();

  const observer = new MutationObserver(updateDisplay);

  observer.observe(boostBtn, {
    attributes: true,
    attributeFilter: ["style", "class"], 
    subtree: false
  });

  window.addEventListener("resize", updateDisplay);
});

function updatePositionInfo() {
  const pos = getImagePosition();
  if (!pos) return;
  
  const size = `${appState.originalWidth}x${appState.originalHeight}`;

  document.getElementById("position-left").textContent = `${pos.left}`;
  document.getElementById("position-top").textContent = `${pos.top}`;
  document.getElementById("position-right").textContent = `${pos.right}`;
  document.getElementById("position-bottom").textContent = `${pos.bottom}`;
  document.getElementById("img-width").textContent = `${pos.width}`;  
  document.getElementById("img-height").textContent = `${pos.height}`;
  document.getElementById("img-scale").textContent = pos.scale;
  document.getElementById("img-angle").textContent = `${pos.angle}°`;

  const imgwidth = pos.width || 0;
  const imgheight = pos.height || 0;
  const rvalue = document.getElementById("r")?.textContent || 1;
  const imgtop = pos.top || 0;
  const imgleft = pos.left || 0;
  const cvswElement = document.getElementById("cvs-w")?.textContent || 0;
  const cvshElement = document.getElementById("cvs-h")?.textContent || 0;
  const imageratio = Number((imgwidth / imgheight).toFixed(2));
  const finalw = (imgwidth * rvalue);
  const finalh = (imgheight * rvalue);
  const finalt = (imgtop * rvalue);
  const finall = (imgleft * rvalue);

  const currentimgw = finalw / 100;
  const currentimgh = finalh / 100;

  const filewvalue = document.getElementById("img-file-w")?.textContent || 0;
  const filehvalue = document.getElementById("img-file-h")?.textContent || 0;

  const dpiW = filewvalue && currentimgw ? filewvalue / currentimgw : 0;
  const dpiH = filehvalue && currentimgh ? filehvalue / currentimgh : 0;
  const dpi = (dpiW + dpiH) / 2;

  appState.finall = finall;
  appState.finalt = finalt;
  appState.finalw= finalw;
  appState.finalh = finalh;
  appState.dpi = dpi;
  appState.printimghight = currentimgh;
  appState.printimgwidth = currentimgw;
  const newcanvasW = (appState.extendwidth * appState.dpi);
  appState.newCanvasWidth = newcanvasW;
   const newcanvasH = (appState.extendheight * appState.dpi);
  appState.newCanvasHeight = newcanvasH;
  const newborder = (0.75 * appState.dpi);
  appState.newBorder = newborder;
  const imageleft = ((finall * appState.dpi) / 100);
  appState.newimageleft = imageleft;
   const imagetop = ((finalt * appState.dpi) / 100);
  appState.newimagetop = imagetop;
  appState.imageWidth = filewvalue;
  appState.imageheight = filehvalue;

  const currentDpi = Number((appState.dpi || 0).toFixed(2));
  if (currentDpi < 35) {
    const zoomInBtn = document.getElementById("zoomIn");
    if (zoomInBtn) {
      zoomInBtn.style.opacity = "0.5";
      zoomInBtn.style.cursor = "not-allowed";
    }
  } else {
    const zoomInBtn = document.getElementById("zoomIn");
    if (zoomInBtn) {
      zoomInBtn.style.opacity = "1";
      zoomInBtn.style.cursor = "pointer";
    }
  }
  updateDpiDisplay();
  document.getElementById("final-dpi").textContent = dpi.toFixed(2);
  document.getElementById("img-f-w").textContent = finalw;
  document.getElementById("img-f-h").textContent = finalh;
  document.getElementById("f-t").textContent = finalt;
  document.getElementById("f-l").textContent = finall;
  document.getElementById("img-ratio").textContent = imageratio;
  document.getElementById("current-img-w").textContent = currentimgw;
  document.getElementById("current-img-h").textContent = currentimgh;

      const hiddenimg = document.getElementById("frame-img-position");
                 const orientationRadio = document.querySelector('input[name="orientation"]:checked');
    const orientation = orientationRadio ? orientationRadio.value : "portrait";
    if(orientation == "portrait"){
        if (hiddenimg) {
                hiddenimg.value = JSON.stringify({
                 area_width: cvswElement,
                  area_height: cvshElement,
                  width: finalw,
                  height: finalh,
                  top: finalt,
                  left: finall,
                });
              }
    }
    else if(orientation == "landscape"){
      if (hiddenimg) {
                hiddenimg.value = JSON.stringify({
                  area_width: cvshElement,
                  area_height: cvswElement,
                  width: finalw,
                  height: finalh,
                  top: finalt,
                  left: finall,
                });
              }
    }
}

function gcd(a, b) {
  return b === 0 ? a : gcd(b, a % b);
}

const dpiElements = document.querySelectorAll(".dpi-num");
const iconElements = document.querySelectorAll(".dpi-state-icon");
const boostBtn = document.querySelector(".boost-img-btn");

boostBtn.style.display = "none";

function updateDpiDisplay() {

  const dpiElement = document.querySelector(".dpi-num");
  const iconElements = document.querySelectorAll(".dpi-state-icon");
  const boostBtn = document.querySelector(".boost-img-btn");
  const confirmBtn = document.querySelector(".image-conform-btn");

  
const currentDpi = Number((appState.dpi || 0).toFixed(2));


  if (!dpiElement || !iconElements.length || !boostBtn) return;

  iconElements.forEach(el => {
    el.innerHTML = "";
  });

  if (currentDpi > 0 && currentDpi < 35) {
    dpiElement.textContent = `Needs Upscale`;
    dpiElement.style.color = "red";

    iconElements.forEach(el => {
      el.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M9.9891 0C4.49317 0 0 4.49317 0 9.9891C0 15.4859 4.49317 20 9.9891 20C15.485 20 20 15.5068 20 9.9891C20 4.47115 15.5068 0 9.9891 0ZM9.9891 18.3208C5.40912 18.3208 1.67946 14.5911 1.67946 10.0111C1.67946 5.43115 5.40912 1.70148 9.9891 1.70148C14.5691 1.70148 18.2987 5.43115 18.2987 10.0111C18.3207 14.5911 14.5909 18.3208 9.9891 18.3208Z" fill="#FF0606"/>
      <path d="M10.1207 4.56252C9.74952 4.56252 9.44421 4.69326 9.20466 4.93365C8.98621 5.1732 8.85547 5.52239 8.85547 5.93651C8.85547 6.24185 8.8774 6.72177 8.92126 7.41931L9.16081 10.9307C9.20466 11.4106 9.29154 11.7379 9.37926 11.9774C9.48806 12.2389 9.70651 12.3696 10.0118 12.3696C10.3172 12.3696 10.5137 12.2389 10.6444 11.9774C10.7532 11.7379 10.841 11.3887 10.8629 10.9526L11.1682 7.33156C11.2121 7.0043 11.2121 6.65511 11.2121 6.34977C11.2121 5.78297 11.1463 5.34691 10.9936 5.04073C10.884 4.7371 10.5787 4.56252 10.1207 4.56252Z" fill="#FF0606"/>
      <path d="M10.0549 13.4844C9.72761 13.4844 9.44421 13.5932 9.20466 13.8336C8.96511 14.0731 8.85547 14.3354 8.85547 14.6627C8.85547 15.0338 8.9862 15.3391 9.2266 15.5348C9.46615 15.7313 9.75039 15.8402 10.0768 15.8402C10.3821 15.8402 10.6655 15.7313 10.9059 15.5129C11.1455 15.2944 11.277 14.6408 11.277 14.6408C11.277 14.3135 11.1682 14.0301 10.9278 13.7906C10.6655 13.5932 10.3813 13.4844 10.0549 13.4844Z" fill="#FF0606"/>
    </svg>`;
    });

    boostBtn.style.display = "flex";
    boostBtn.classList.add("show");

  } else if (currentDpi >= 35) {
    dpiElement.textContent = `Good To Print`;
    dpiElement.style.color = "green";

    iconElements.forEach(el => {
      el.innerHTML =`<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M10 0C4.48421 0 0 4.48421 0 10C0 15.5158 4.48421 20 10 20C15.5158 20 20 15.5158 20 10C20 4.48421 15.5158 0 10 0ZM10 17.8105C5.68421 17.8105 2.18947 14.2947 2.18947 10C2.18947 5.70526 5.68421 2.18947 10 2.18947C14.3158 2.18947 17.8105 5.68421 17.8105 10C17.8105 14.3158 14.3158 17.8105 10 17.8105Z" fill="#1B8600"/>
<path d="M12.7139 6.92258L8.90337 10.7542L7.28232 9.13311C6.86127 8.71205 6.16653 8.71205 5.74548 9.13311C5.32442 9.55416 5.32442 10.2489 5.74548 10.6699L8.14548 13.0699C8.356 13.2805 8.62969 13.3857 8.92443 13.3857C9.21916 13.3857 9.49285 13.2805 9.70337 13.0699L14.2928 8.48047C14.7139 8.05942 14.7139 7.36469 14.2928 6.94363C13.8507 6.50153 13.156 6.50153 12.7139 6.92258Z" fill="#1B8600"/>
</svg>`;

    });

    boostBtn.classList.remove("show");
    boostBtn.style.display = "none";

  } else if (currentDpi === 0) {
    boostBtn.classList.remove("show");

    setTimeout(() => {
      if (!boostBtn.classList.contains("show")) {
        boostBtn.style.display = "none";
        if (confirmBtn) {
          confirmBtn.style.display = "flex";
        }
      }
    }, 300);
  }
}

function updateFrameFromPixels(width, height, width1, height1) {
  canvas.setWidth(width + appState.outerMargin * 2);
  canvas.setHeight(height + appState.outerMargin * 2);
  requestCanvasZoomRecalc();
  const frnheight = appState.originalHeight;
  const frmwidth = appState.originalWidth;
  let size = `${frmwidth}x${frnheight}`;

  const sortedSize = [frmwidth, frnheight].sort((a, b) => a - b).join("x");

  let innerPadding;
  if (window.innerWidth < 680) {
switch (sortedSize) {
  
  case "900x900":
    innerPadding =  150 / 4.5;
    break;
  case "1100x1100":
    innerPadding =  150 / 5.5;
    break;
  case "1100x1300":
    innerPadding =  150 / 6.5;
    break;
  case "1100x1500":
    innerPadding =  150 / 7.5;
    break;
  case "1200x1500":
    innerPadding =  150 / 7.5;
    break;
  case "1300x1300":
    innerPadding =  150 / 6.5;
    break;
  case "1300x2300":
    innerPadding =  150 / 11.5;
    break;
  case "1400x1700":
    innerPadding =  150 / 8.5;
    break;
  case "1800x1800":
    innerPadding =  300 / 9;
    break;
  case "1800x2200":
    innerPadding =  300 / 11;
    break; 
  case "1500x2100":
    innerPadding =  150 / 10.5;
    break;
  case "1500x2700":
    innerPadding =  150 / 13.5;
    break;
  case "1500x3900":
    innerPadding =  150 / 19.5;
    break;
  case "1700x1700":
    innerPadding =  150 / 8.5;
    break;
  case "2200x2200":
    innerPadding =  300 / 9.5;
    break;
  case "2200x2600":
    innerPadding =  300 / 13;
    break;
  case "1900x2700":
    innerPadding =  150 / 13.5;
    break;
  case "1900x3500":
    innerPadding =  150 / 17.5;
    break;
  case "1900x5100":
    innerPadding =  150 / 25.5;
    break;
  case "2100x2100":
    innerPadding =  150 / 10.5;
    break;
  case "2400x3000":
    innerPadding =  300 / 15;
    break;
  case "2100x2900": 
    innerPadding =  150 / 14.5;
    break;
  case "2300x2300":
    innerPadding =  150 / 11.5;
    break;
  case "2300x2700":
    innerPadding =  150 / 13.5; 
    break;
  case "2300x3100":
    innerPadding =  150 / 15.5;
    break;
  case "2300x3300":
    innerPadding =  150 / 16.5;
    break;
  case "2300x4300":
    innerPadding =  150 / 21.5;
    break;
  case "2300x6300":
    innerPadding =  150 / 31.5;
    break;
  case "2700x2700":
    innerPadding =  150 / 13.5;
    break;
  case "2700x3300":
    innerPadding =  150 / 16.5;
    break;
  case "2700x3500":
    innerPadding =  150 / 17.5;
    break;
  case "3000x4200":
    innerPadding =  300 / 21;
    break;
  case "2700x5100":
    innerPadding =  150 / 25.5;
    break;
  case "2900x2900":
    innerPadding =  150 / 14.5;
    break;
  case "2900x4300":
    innerPadding =  150 / 21.5;
    break;
  case "3100x3100":
    innerPadding =  150 / 16.5;
    break;
  case "3100x4300":
    innerPadding =  150 / 21.5;
    break;
  case "3300x3300":
    innerPadding =  150 / 16.5;
    break;
  case "3300x4300":
    innerPadding =  150 / 21.5;
    break;
  case "3300x6300":
    innerPadding =  150 / 31.5;
    break;
  case "3500x3500":
    innerPadding =  150 / 17.5;
    break;
  case "3500x5100":
    innerPadding =  150 / 25.5;
    break;
  case "3900x3900":
    innerPadding =  150 / 19.5;
    break;
  case "4000x4000":
    innerPadding =  150 / 20;
    break;
  case "4300x5800":
    innerPadding =  150 / 29;
    break;
  case "4300x6300":
    innerPadding =  150 / 31.5;
    break;
  default:
    innerPadding = null;
    break;
}

} else {
  
switch (sortedSize) {
  
  case "900x900":
    innerPadding = 150 / 2.25;
    break;
  case "1100x1100":
    innerPadding = 150 / 2.75;
    break;
  case "1100x1300":
    innerPadding = 150 / 3.25;
    break;
  case "1100x1500":
    innerPadding = 150 / 3.75;
    break;
  case "1200x1500":
    innerPadding = 150 / 3.75;
    break;
  case "1300x1300":
    innerPadding = 150 / 3.25;
    break;
  case "1300x2300":
    innerPadding = 150 / 5.75;
    break;
  case "1400x1700":
    innerPadding = 150 / 4.25;
    break;
  case "1800x1800":
    innerPadding = 300 / 4.5;
    break;
  case "1800x2200":
    innerPadding = 300 / 5.5;
    break;
  case "1500x2100":
    innerPadding = 150 / 5.25;
    break;
  case "1500x2700":
    innerPadding = 150 / 6.75;
    break;
  case "1500x3900":
    innerPadding = 150 / 9.75;
    break;
  case "1700x1700":
    innerPadding = 150 / 4.25;
    break;
  case "2200x2200":
    innerPadding = 300 / 5.5;
    break;
  case "2200x2600":
    innerPadding = 300 / 6.5;
    break;
  case "1900x2700":
    innerPadding = 150 / 6.75;
    break;
  case "1900x3500":
    innerPadding = 150 / 8.75;
    break;
  case "1900x5100":
    innerPadding = 150 / 12.75;
    break;
  case "2100x2100":
    innerPadding = 150 / 5.25;
    break;
  case "2400x3000":
    innerPadding = 300 / 7.5;
    break;
  case "2100x2900":
    innerPadding = 150 / 7.25;
    break;
  case "2300x2300":
    innerPadding = 150 / 5.75;
    break;
  case "2300x2700":
    innerPadding = 150 / 6.75;
    break;
  case "2300x3100":
    innerPadding = 150 / 7.75;
    break;
  case "2300x3300":
    innerPadding = 150 / 8.25;
    break;
  case "2300x4300":
    innerPadding = 150 / 10.75;
    break;
  case "2300x6300":
    innerPadding = 150 / 15.75;
    break;
  case "2700x2700":
    innerPadding = 150 / 6.75;
    break;
  case "2700x3300":
    innerPadding = 150 / 8.25;
    break;
  case "2700x3500":
    innerPadding = 150 / 8.75;
    break;
  case "3000x4200":
    innerPadding = 300 / 10.5;
    break;
  case "2700x5100":
    innerPadding = 150 / 12.75;
    break;
  case "2900x2900":
    innerPadding = 150 / 7.25;
    break;
  case "2900x4300":
    innerPadding = 150 / 10.75;
    break;
  case "3100x3100":
    innerPadding = 150 / 7.75;
    break;
  case "3100x4300":
    innerPadding = 150 / 10.75;
    break;
  case "3300x3300":
    innerPadding = 150 / 8.25;
    break;
  case "3300x4300":
    innerPadding = 150 / 10.75;
    break;
  case "3300x6300":
    innerPadding = 150 / 15.75;
    break;
  case "3500x3500":
    innerPadding = 150 / 8.75;
    break;
  case "3500x5100":
    innerPadding = 150 / 12.75;
    break;
  case "3900x3900":
    innerPadding = 150 / 9.75;
    break;
  case "4000x4000":
    innerPadding = 150 / 10;
    break;
  case "4300x5800":
    innerPadding = 150 / 14.5;
    break;
  case "4300x6300":
    innerPadding = 150 / 15.75;
    break;
  default:
    innerPadding = null;
    break;
}
}

  if (!Number.isFinite(innerPadding)) {
    innerPadding = 0;
  }

  appState.innerPadding = innerPadding;
  appState.borderSize = innerPadding;
  appState.innerWidth = width - innerPadding * 2;
  appState.innerHeight = height - innerPadding * 2;

  canvas.clear();
 canvas.setBackgroundColor("#ffffff", canvas.renderAll.bind(canvas)); 
  if (appState.uploadedImage) {
    appState.uploadedImage.clipPath = null;
    appState.uploadedImage.originX = 0;
    appState.uploadedImage.originY = 0;
    appState.uploadedImage.left = 0;
    appState.uploadedImage.top = 0;
    appState.uploadedImage.scaleToWidth(width);
    appState.uploadedImage.scaleToHeight(height);

    canvas.add(appState.uploadedImage);
    canvas.setActiveObject(appState.uploadedImage);
  }

  const borderSize = innerPadding;

function drawBorderOnTop() {
  const ctx = canvas.contextTop;
  if (!ctx) return;

  canvas.clearContext(canvas.contextTop);

  const bw = canvas.getWidth();
  const bh = canvas.getHeight();

  ctx.save();

  
 const dashOffset = 0.5; 
  ctx.setLineDash([5, 2]);
  ctx.lineWidth = 0.5;
  ctx.strokeStyle = "#000";

  ctx.beginPath(); ctx.moveTo(0, dashOffset); ctx.lineTo(bw, dashOffset); ctx.stroke(); 
  ctx.beginPath(); ctx.moveTo(0, bh - dashOffset); ctx.lineTo(bw, bh - dashOffset); ctx.stroke(); 
  ctx.beginPath(); ctx.moveTo(dashOffset, 0); ctx.lineTo(dashOffset, bh); ctx.stroke(); 
  ctx.beginPath(); ctx.moveTo(bw - dashOffset, 0); ctx.lineTo(bw - dashOffset, bh); ctx.stroke(); 


  ctx.beginPath(); ctx.moveTo(0, borderSize + dashOffset); ctx.lineTo(bw, borderSize + dashOffset); ctx.stroke(); 
  ctx.beginPath(); ctx.moveTo(0, bh - borderSize - dashOffset); ctx.lineTo(bw, bh - borderSize - dashOffset); ctx.stroke(); 
  ctx.beginPath(); ctx.moveTo(borderSize + dashOffset,0); ctx.lineTo(borderSize + dashOffset, bh); ctx.stroke(); 
  ctx.beginPath(); ctx.moveTo(bw - borderSize - dashOffset, 0); ctx.lineTo(bw - borderSize - dashOffset, bh); ctx.stroke();

  ctx.setLineDash([]);

 
  const mirrorPreviewDrawn = drawMirrorPreviewOnTop(ctx, borderSize);

  if (!mirrorPreviewDrawn) {
    ctx.fillStyle = "#ffffff00";

    ctx.fillRect(0, 0, bw, borderSize); 
    ctx.fillRect(0, bh - borderSize, bw, borderSize); 
    ctx.fillRect(0, borderSize, borderSize, bh - borderSize * 2); 
    ctx.fillRect(bw - borderSize, borderSize, borderSize, bh - borderSize * 2); 

    ctx.fillStyle = "black";
    const fontSize = 8;
    ctx.font = `${fontSize}px sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";

    ctx.fillText("SIDE AND BACK", bw / 2, borderSize / 2);
    ctx.fillText("SIDE AND BACK", bw / 2, bh - borderSize / 2);

    ctx.save();
    ctx.translate(borderSize / 2, bh / 2);
    ctx.rotate(Math.PI / 2);
    ctx.fillText("SIDE AND BACK", 0, 0);
    ctx.restore();

    ctx.save();
    ctx.translate(bw - borderSize / 2, bh / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText("SIDE AND BACK", 0, 0);
    ctx.restore();
  }

  ctx.restore();
}

  window.drawBorderOnTop = drawBorderOnTop;
  
  canvas.off("after:render");
  canvas.on("after:render", drawBorderOnTop);
  canvas.requestRenderAll();
  updatePositionInfo();
  updateCenterLines();
}

function bringCenterLinesToFront() {
  if (vCenterLine) {
    canvas.moveTo(vCenterLine, 9999);
  }
  if (hCenterLine) {
    canvas.moveTo(hCenterLine, 9999);
  }
  canvas.requestRenderAll();
}
canvas.on('after:render', function() {
  bringCenterLinesToFront();
});

function removeBorderFromTop() {
  const ctx = canvas.contextTop;
  if (!ctx) return;
  canvas.clearContext(ctx);
  canvas.requestRenderAll();
}
window.removeBorderFromTop = removeBorderFromTop;

function coverFrame1() {

    if (!appState.uploadedImage) return;

    const img = appState.uploadedImage;
    const orientationRadio = document.querySelector('input[name="orientation"]:checked');
    const orientation = orientationRadio ? orientationRadio.value : "portrait";

      let canvasWidth, canvasHeight;
      let W, H;
      let scaleX, scaleY;

      if(orientation === "portrait")  { // portrait

          canvasWidth = appState.selectedWidth;
          canvasHeight = appState.selectedHeight;

          W = img.width;
          H = img.height;

          scaleX = appState.innerWidth / W;
          scaleY = appState.innerHeight / H;
      }
      else  {

          canvasWidth = appState.selectedWidth;
          canvasHeight = appState.selectedHeight;

          W = img.width;
          H = img.height;

          scaleX = appState.innerWidth / W;
          scaleY = appState.innerHeight / H;

      }

    let newScale = Math.max(scaleX, scaleY);
    if (!isFinite(newScale) || newScale <= 0) newScale = 1;

    img.scaleX = newScale;
    img.scaleY = newScale;
    appState.scaleFactor = newScale;

    const centerX = canvasWidth / 2;
    const centerY = canvasHeight / 2;

    img.set({
        left: centerX,
        top: centerY,
        originX: 'center',
        originY: 'center'
    });

    updateMovementConstraints(); 
    centerImage(); 
    img.setCoords();
    updatePositionInfo();
    canvas.requestRenderAll();
    syncZoomSlider();
    drawBorderOnTop();
     updateCenterLines();
}

function FitFrontFrame() {

    if (!appState.uploadedImage) return;

    const img = appState.uploadedImage;
    const orientationRadio = document.querySelector('input[name="orientation"]:checked');
    const orientation = orientationRadio ? orientationRadio.value : "portrait";

      let canvasWidth, canvasHeight;
      let W, H;
      let scaleX, scaleY;

      if(orientation === "portrait")  { // portrait

          canvasWidth = appState.selectedWidth;
          canvasHeight = appState.selectedHeight;

          W = img.width;
          H = img.height;

          scaleX = appState.innerWidth / W;
          scaleY = appState.innerHeight / H;
      }
      else  {

          canvasWidth = appState.selectedWidth;
          canvasHeight = appState.selectedHeight;

          W = img.width;
          H = img.height;

          scaleX = appState.innerWidth / W;
          scaleY = appState.innerHeight / H;

      }

    let newScale = Math.min(scaleX, scaleY);
    if (!isFinite(newScale) || newScale <= 0) newScale = 1;

    img.scaleX = newScale;
    img.scaleY = newScale;
    appState.scaleFactor = newScale;

    const centerX = canvasWidth / 2;
    const centerY = canvasHeight / 2;

    img.set({
        left: centerX,
        top: centerY,
        originX: 'center',
        originY: 'center'
    });

    updateMovementConstraints(); 
    centerImage(); 
    img.setCoords();
    updatePositionInfo();
    canvas.requestRenderAll();
    setTimeout(() => {
    syncZoomSlider();
  }, 100);
    drawBorderOnTop();

}
function coverFrame(bgColor) {

    if (!isEdgesEnabled()) {
        return;
    }

    if (!bgColor) bgColor = "white";

    bgColor = bgColor.toLowerCase() === "black" ? "black" : "white";

    if (bgColor === "black") {
      appState.canvasBorderColor = "#000";
    } 
    else if (bgColor === "white") {
      appState.canvasBorderColor = "#fff";
    } 
    else {
      appState.canvasBorderColor = "#fff";
    }

     canvas.setBackgroundColor("#ffffff", canvas.renderAll.bind(canvas));
    if (!appState.uploadedImage) return;

    const img = appState.uploadedImage;
    const orientationRadio = document.querySelector('input[name="orientation"]:checked');
    const orientation = orientationRadio ? orientationRadio.value : "portrait";

      let canvasWidth, canvasHeight;
      let W, H;
      let scaleX, scaleY;

      if(orientation === "portrait")  { // portrait

          canvasWidth = appState.selectedWidth;
          canvasHeight = appState.selectedHeight;

          W = img.width;
          H = img.height;

          scaleX = appState.innerWidth / W;
          scaleY = appState.innerHeight / H;
      }
      else  {

          canvasWidth = appState.selectedWidth;
          canvasHeight = appState.selectedHeight;

          W = img.width;
          H = img.height;

          scaleX = appState.innerWidth / W;
          scaleY = appState.innerHeight / H;

      }

    let newScale = Math.max(scaleX, scaleY);
    if (!isFinite(newScale) || newScale <= 0) newScale = 1;

    img.scaleX = newScale;
    img.scaleY = newScale;
    appState.scaleFactor = newScale;

    const centerX = canvasWidth / 2;
    const centerY = canvasHeight / 2;

    img.set({
        left: centerX,
        top: centerY,
        originX: 'center',
        originY: 'center'
    });

    updateMovementConstraints(); 
    centerImage(); 
    img.setCoords();
    updatePositionInfo();
    canvas.requestRenderAll();
      setTimeout(() => {
    syncZoomSlider();
  }, 100);
  
    drawBorderOnTop();
}

function fitImageToFrame(cover = false) {
  if (!appState.uploadedImage) {
    return;
  }

  const W = appState.uploadedImage.width;
  const H = appState.uploadedImage.height;

  const scaleX = appState.selectedWidth / W;
  const scaleY = appState.selectedHeight / H;

  let newScale = cover ? Math.max(scaleX, scaleY) : Math.min(scaleX, scaleY);
  if (!isFinite(newScale) || newScale <= 0) {
    newScale = 1;
  }

  appState.uploadedImage.scaleX = newScale;
  appState.uploadedImage.scaleY = newScale;
  appState.scaleFactor = newScale;

  updateMovementConstraints(); 
  centerImage();
  appState.uploadedImage.setCoords();
  updatePositionInfo();
  appState.canvasBorderColor = "#00000060";
  drawBorderOnTop();
   setTimeout(() => {
    syncZoomSlider();
  }, 100);
  
  canvas.requestRenderAll();
}

function centerImage() {
  if (!appState.uploadedImage) return;
  const centerX = appState.selectedWidth / 2;
  const centerY =appState.selectedHeight / 2;
  appState.uploadedImage.originX = "center";
  appState.uploadedImage.originY = "center";
  appState.uploadedImage.left = centerX;
  appState.uploadedImage.top = centerY;
  appState.uploadedImage.setCoords();
  canvas.requestRenderAll();
    setTimeout(() => {
    syncZoomSlider();
  }, 100);
  
  updatePositionInfo();
}

// document.getElementById("zoomIn").addEventListener("click", () => {
//   if (appState.uploadedImage) {
//     appState.scaleFactor *= 1.1;
//     appState.uploadedImage.scaleX = appState.scaleFactor;
//     appState.uploadedImage.scaleY = appState.scaleFactor;
//     appState.uploadedImage.setCoords();
//     updateMovementConstraints();
//     centerImage();
//     updatePositionInfo();
//     syncZoomSlider(); // Add this to update the slider
//   }
// });
// document.getElementById("zoomOut").addEventListener("click", () => {
//   if (appState.uploadedImage) {
//     // Allow unlimited zoom out by removing any minimum check
//     appState.scaleFactor *= 0.9;
//     appState.uploadedImage.scaleX = appState.scaleFactor;
//     appState.uploadedImage.scaleY = appState.scaleFactor;
//     appState.uploadedImage.setCoords();
//     updateMovementConstraints();
//     centerImage();
//     updatePositionInfo();
//     syncZoomSlider(); // Add this to update the slider
//   }
// });

function updateFrameSize(selectedOption) {
    // Get orientation selection
    const selectedRadio = document.querySelector('input[name="orientation"]:checked');
    const selectedOrientation = selectedRadio ? selectedRadio.value : "portrait";
      const selectedsize = document.querySelector('input[name="frameSize"]:checked');
    // Get frame size data from selected option
    const originalsize = selectedOption.getAttribute("data-original-size");
    const [width1, height1] = originalsize.split("x").map(Number);
  
  document.querySelectorAll(".selected-size").forEach(el => {
    el.textContent = selectedsize.value;
  });

     let dataratio;
 let size;
  if (window.innerWidth < 680) {
    size = selectedOption.getAttribute("data-pixel-mobile");
    dataratio = selectedOption.getAttribute("data-ratio-mobile");
  } else {
    size = selectedOption.getAttribute("data-pixel-desktop");
    dataratio = selectedOption.getAttribute("data-ratio-desktop");
  }

    const frmsize = selectedOption.getAttribute("data-frmsize");
    const [width, height] = size.split("x").map(Number);
    const [frmwidth, frmheight] = frmsize.replace(/″/g, '').split('×').map(s => Number(s.trim()));
    
    // Calculate extended dimensions
    const extendwidth = frmwidth + 3;
    const extendheight = frmheight + 3;
    
    // Set values based on orientation
    if (selectedOrientation === "portrait") {
        appState.originalWidth = width1;
        appState.originalHeight = height1;
        appState.selectedWidth = width;
        appState.selectedHeight = height;
        appState.extendheight = extendheight;
        appState.extendwidth = extendwidth;
    } else { // landscape
        appState.originalWidth = height1; 
        appState.originalHeight = width1;
        appState.selectedWidth = height;
        appState.selectedHeight = width;
        appState.extendheight = extendwidth;
        appState.extendwidth = extendheight;
    }
    
    // Update UI elements
    updateFrameFromPixels(appState.selectedWidth, appState.selectedHeight, appState.originalWidth, appState.originalHeight);
    
    const cvswElement = document.getElementById("cvs-w");
    const cvshElement = document.getElementById("cvs-h");
    const orgWElement = document.getElementById("org-w");
    const orgHElement = document.getElementById("org-h");
    const frnWElement = document.getElementById("frm-w");
    const frmHElement = document.getElementById("frm-h");
    const ratioElement = document.getElementById("r");
    
    if (orgWElement) orgWElement.textContent = appState.originalWidth;
    if (orgHElement) orgHElement.textContent = appState.originalHeight;
    if (frnWElement) frnWElement.textContent = appState.selectedWidth;
    if (frmHElement) frmHElement.textContent = appState.selectedHeight;
    if (ratioElement) ratioElement.textContent = dataratio;
    if (cvswElement) cvswElement.textContent = appState.originalWidth;
    if (cvshElement) cvshElement.textContent = appState.originalHeight;
    
    // Handle canvas updates
    canvas.setWidth(appState.selectedWidth);
    canvas.setHeight(appState.selectedHeight);
    requestCanvasZoomRecalc();
    
    // Update all canvas objects
    canvas.getObjects().forEach(obj => {
        obj.set({
            scaleX: obj.scaleX,
            scaleY: obj.scaleY,
            left: obj.left,
            top: obj.top
        });
        obj.setCoords();
    });
    
    canvas.renderAll();
    
    // Handle uploaded image if exists
    if (appState.uploadedImage) {
        appState.uploadedImage.clipPath = appState.clipPath;
        canvas.add(appState.uploadedImage);
        FitFrontFrame();
    }
    
    updatePositionInfo();
    
    // Handle wrap option
    const checkedWrap = document.querySelector('.wrap-option input:checked');
    appState.selectedWrap = checkedWrap ? checkedWrap.value : null;
    
    if (appState.selectedWrap === "black") {
        coverFrame("black");
    } else if (appState.selectedWrap === "white") {
        coverFrame("white");
    } else if (appState.selectedWrap === "fit") {
        FitFrontFrame();
    }
    
    // DPI display logic
    updateDpiDisplay();
}

// Function to handle orientation radio button changes
function handleOrientationChange() {
    // Get the currently selected frame size option
    const selectedSizeOption = document.querySelector('#frameSizeOptions [name="frameSize"]:checked');
    if (selectedSizeOption) {
        updateFrameSize(selectedSizeOption);
    }
}

// Event listeners
document.getElementById("frameSizeOptions").addEventListener("change", function(e) {
    if (e.target.name === "frameSize") {
        updateFrameSize(e.target);
    }
});

document.getElementById("frameOrientationOptions").addEventListener("change", function(e) {
    if (e.target.name === "orientation") {
        handleOrientationChange();
    }
});

// Initialize on load
window.addEventListener("load", () => {
    const selectedOption = document.querySelector('#frameSizeOptions [name="frameSize"]:checked');
    if (selectedOption) {
        updateFrameSize(selectedOption);
    }
    
    // Add orientation change listeners to radio buttons
    const orientationRadios = document.querySelectorAll('input[name="orientation"]');
    orientationRadios.forEach(radio => {
        radio.addEventListener('change', handleOrientationChange);
    });
});


window.addEventListener("load", () => {
  const selectedOption = document.querySelector('#frameOrientationOptions [ name="orientation" ]:checked');
  if (selectedOption) {
    updateFrameSize(selectedOption);
  }
});

canvas.on('object:moving', function(e) {
  const obj = e.target;
  
  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;
  
  // Get object center point
  const objCenter = obj.getCenterPoint();
  
  // Calculate distances from center
  const distX = Math.abs(objCenter.x - centerX);
  const distY = Math.abs(objCenter.y - centerY);
  
  // Remove existing center lines first
  if (vCenterLine) {
    canvas.remove(vCenterLine);
    vCenterLine = null;
  }
  if (hCenterLine) {
    canvas.remove(hCenterLine);
    hCenterLine = null;
  }
  
  // Check if object should snap to vertical center
  if (distX < THRESHOLD) {
    // For center-origin objects, just set left to centerX
    obj.set({ 
      left: centerX 
    });
    
    // Create and show vertical center line
    vCenterLine = new fabric.Line(
      [centerX, 0, centerX, canvas.height], 
      {
        stroke: 'red',
        strokeWidth: 1,
        selectable: false,
        evented: false,
        opacity: 0.7, // Slightly transparent
        name: 'centerLine'
      }
    );
    
    canvas.add(vCenterLine);
    // Ensure the line is on top
    canvas.moveTo(vCenterLine, 9999);
  }
  
  // Check if object should snap to horizontal center
  if (distY < THRESHOLD) {
    // For center-origin objects, just set top to centerY
    obj.set({ 
      top: centerY 
    });
    
    // Create and show horizontal center line
    hCenterLine = new fabric.Line(
      [0, centerY, canvas.width, centerY], 
      {
        stroke: 'red',
        strokeWidth:1,
        selectable: false,
        evented: false,
        opacity: 0.7, // Slightly transparent
        name: 'centerLine'
      }
    );
    
    canvas.add(hCenterLine);
    // Ensure the line is on top
    canvas.moveTo(hCenterLine, 9999);
  }
  
  updatePositionInfo();
  obj.setCoords();
  
  // If object was snapped, we need to render
  if (distX < THRESHOLD || distY < THRESHOLD) {
    canvas.requestRenderAll();
  }
});

// Add this function to always keep center lines on top
canvas.on('object:added', function(e) {
  if (e.target.name === 'centerLine') {
    canvas.moveTo(e.target, 9999);
  }
});

// Also update your object:modified event to properly handle lines
canvas.on('object:modified', function(e) {
  // Only remove center lines if we're modifying a non-line object
  if (e.target.name !== 'centerLine') {
    if (vCenterLine) {
      canvas.remove(vCenterLine);
      vCenterLine = null;
    }
    if (hCenterLine) {
      canvas.remove(hCenterLine);
      hCenterLine = null;
    }
  }
  
  updatePositionInfo();
  canvas.requestRenderAll();
});


function uploadImageToAPI(file) {
  const formData = new FormData();
  const userId = window.shopifyCustomerId || "guest";
    const sessionId = getLocalStorage1Day("sessionId") || "none";
 formData.append('file', file);
    formData.append('customerId', userId);
    formData.append('sessionId', sessionId);
     formData.append('megamenu', "true");
console.log(file);
  fetch(`${window.Prompt2Prints.apiBase}/upload-image`, {
    method: "POST",
              headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
    body: formData
  })
  .then(res => res.json())
  .then(data => {
    // ✅ Store cloudfrontLink in localStorage
      if (data?.cloudfrontLink) {
        localStorage.setItem("pdpUploadedImage", data.cloudfrontLink);
      } else {
        console.warn("cloudfrontLink not found in API response");
      }
 const imageUpscale = document.querySelector('input[name="properties[_pdp-allow-upscale]"]');
const imageUpscaletag = document.querySelector('input[name="properties[_pdp-img-tag]"]');

if (!imageUpscale || !imageUpscaletag) {
  console.warn("Upscale inputs not found");
  return;
}

const flag = (data.flag || "").toLowerCase();

if (flag === "standard") {
  imageUpscale.value = "true";
  imageUpscaletag.value = "Standard";
} 
else if (flag === "professional") {
  imageUpscale.value = "false";
  imageUpscaletag.value = "Professional";
} 
else {
  imageUpscale.value = "";
  imageUpscaletag.value = "";
}

// Optional: also update attribute for Shopify forms
imageUpscale.setAttribute("value", imageUpscale.value);
imageUpscaletag.setAttribute("value", imageUpscaletag.value);
  })
  .catch(err => {
    console.error("Image upload failed:", err);
  });
}

uploadInput.addEventListener("change", function (e) {
  const file = e.target.files[0];
  if (!file) return;


  const allowedTypes = [
    "image/jpeg",
    "image/png",
    "image/heic",
    "image/heif"
  ];

  if (!allowedTypes.includes(file.type)) {
    alert("Only JPEG, PNG, or HEIC images are allowed.");
    uploadInput.value = ""; 
    return;
  }
appState.uploadimgsize = +(file.size / (1024 * 1024)).toFixed(2);
  /* ========================== */

  // 🔹 Send image to API
  uploadImageToAPI(file);

  const img = new Image();
  img.onload = function () {
    galleryWrapper.style.display = "none";
    uploadInputwrap.style.display = "none";
    customForm.style.display = "block";
    requestCanvasZoomRecalc();

    const reader = new FileReader();
    reader.onload = function (f) {
      const mainImgWrap = document.querySelector(".main-img-wrap");
      if (mainImgWrap) {
        mainImgWrap.setAttribute("data-main-img", f.target.result);
      }

      fabric.Image.fromURL(f.target.result, function (fabricImg) {
        cleanupCropSelection();
        appState.uploadedImage = fabricImg;
        appState.cropState = { isCropped: false, backup: null, isSelecting: false, selectionRect: null };
        updateCropButtonState();

        const imgfileWElement = document.getElementById("img-file-w");
        const imgfileHElement = document.getElementById("img-file-h");

        if (imgfileWElement) imgfileWElement.textContent = fabricImg.width;
        if (imgfileHElement) imgfileHElement.textContent = fabricImg.height;

        fabricImg.set({
          selectable: true,
          evented: true,
          hasBorders: false,
          hasControls: false,
          lockRotation: true,
          lockScalingFlip: true,
          lockUniScaling: true,
          originX: "center",
          originY: "center",
          clipPath: appState.clipPath
        });

        fabricImg.setControlsVisibility({
          mt: false,
          mb: false,
          ml: false,
          mr: false,
          mtr: false
        });

        canvas.add(fabricImg);
        setMovementConstraints();
        canvas.setActiveObject(fabricImg);
        canvas.moveTo(fabricImg, 2);

        if (!isEdgesEnabled()) {
           // fitImageToFrame(true);
     FitFrontFrame();
        } else {
           FitFrontFrame();
        }

        

        syncZoomSlider();
      });
    };

    reader.readAsDataURL(file);

    document.querySelectorAll(".image-conform-btn").forEach(div => {
      div.style.pointerEvents = "auto";
      div.style.opacity = "1";
    });
  };

  img.src = URL.createObjectURL(file);
});

const slider = document.getElementById("zoomSlider");
const zoomInBtn = document.getElementById("zoomIn");
const zoomOutBtn = document.getElementById("zoomOut");
const zoomLabel = document.getElementById("zoomLabel");

const canvasW = parseFloat(document.getElementById("frm-w")?.textContent) || 1;
const canvasH = parseFloat(document.getElementById("frm-h")?.textContent) || 1;

let imgWidthInches = 6;
let imgHeightInches = 4;
let scale = 1;

function isEdgesEnabled() {
    const blackCheckbox = document.getElementById("enable-edges-black");
    const whiteCheckbox = document.getElementById("enable-edges-white");

    const blackChecked = blackCheckbox ? blackCheckbox.checked : false;
    const whiteChecked = whiteCheckbox ? whiteCheckbox.checked : false;

    return blackChecked || whiteChecked;
}

function updateSliderBackground(slider) {
  if (!slider) return;
  
  const value = ((slider.value - slider.min) / (slider.max - slider.min)) * 100;
  
  const currentDpi = Number((appState.dpi || 0).toFixed(2));
  
  let backgroundColor;
  if (currentDpi < 35) {
    backgroundColor = `linear-gradient(to right, #1F8FE5 ${value}%, #ff4444 ${value}%)`;
    slider.classList.add('dpi-warning-slider');
  } else {
    backgroundColor = `linear-gradient(to right, #1F8FE5 ${value}%, rgb(255, 255, 255) ${value}%)`;
    slider.classList.remove('dpi-warning-slider');
  }
  
  slider.style.background = backgroundColor;
}

function isZoomAllowed(newZoom) {
  const currentDpi = Number((appState.dpi || 0).toFixed(2));
  if (currentDpi < 35) {
    if (appState.uploadedImage) {
      const baseScale = getBaseScale();
      const currentZoom = appState.uploadedImage.scaleX / baseScale;
      if (newZoom > currentZoom) {
        console.warn("Cannot zoom in further - DPI is below 40");
        return false;
      }
      return true;
    }
  }
  return true;
}

function initZoomSlider() {
  const slider = document.getElementById("zoomSlider");
  if (!slider) return;
    slider.min = String(appState.minZoom * 100);
  slider.max = String(appState.maxZoom * 100);
  slider.value = String(appState.zoom * 100);
  updateSliderBackground(slider);
   syncZoomSlider();
}
document.addEventListener("DOMContentLoaded", function() {
  initZoomSlider();
  
  // Zoom slider event
  const slider = document.getElementById("zoomSlider");
  if (slider) {
    slider.addEventListener("input", function() {
      handleZoomSlider(this);
    });
  }
  
  // Zoom button events
  const zoomInBtn = document.getElementById("zoomIn");
  const zoomOutBtn = document.getElementById("zoomOut");
  
  if (zoomInBtn) {
    zoomInBtn.addEventListener("click", zoomIn);
  }
  
  if (zoomOutBtn) {
    zoomOutBtn.addEventListener("click", zoomOut);
  }
});

function calculateCoverZoom() {
  if (!appState.uploadedImage) {
    return 1;
  }

  const img = appState.uploadedImage;
  const imgElement = img._element;
  if (!imgElement) {
    return 1;
  }
  
    const canvasWidth = appState.selectedWidth;
    const canvasHeight = appState.selectedHeight;
    const W = img.width;
    const H = img.height;

    const scaleX = appState.innerWidth / W;
    const scaleY = appState.innerHeight / H;

    let newScale = Math.max(scaleX, scaleY);
    if (!isFinite(newScale) || newScale <= 0) newScale = 1;

    img.scaleX = newScale;
    img.scaleY = newScale;
    appState.scaleFactor = newScale;

    const centerX = canvasWidth / 2;
    const centerY = canvasHeight / 2;
    const fitScale = Math.max(scaleX, scaleY);
    const finalZoom = Math.min(1, fitScale);

    return finalZoom;
}

function getBaseScale() {
  if (!appState.uploadedImage) return 1;
  
  const img = appState.uploadedImage;
  const canvasWidth = appState.selectedWidth;
  const canvasHeight = appState.selectedHeight;
  
  const scaleX = canvasWidth / img.width;
  const scaleY = canvasHeight / img.height;
  
  return Math.min(scaleX, scaleY);
}

function updateZoom(newZoom) {
  if (!appState.uploadedImage) {
    console.warn("No uploaded image to zoom");
    return;
  }
  
  try {
    const baseScale = getBaseScale();
    const currentZoom = appState.uploadedImage.scaleX / baseScale;
    
    if (!isZoomAllowed(newZoom)) {
     
      newZoom = currentZoom;

      const slider = document.getElementById("zoomSlider");
      if (slider) {
        slider.value = String(Math.round(currentZoom * 100));
        updateSliderBackground(slider);
      }
      
      return;
    }
    
    newZoom = Math.max(appState.minZoom, Math.min(appState.maxZoom, newZoom));
    appState.zoom = newZoom;
    
    if (baseScale <= 0 || !isFinite(baseScale)) {
      console.warn("Invalid base scale for zoom:", baseScale);
      return;
    }
    
    const finalScale = baseScale * appState.zoom;

    appState.uploadedImage.scaleX = finalScale;
    appState.uploadedImage.scaleY = finalScale;
    appState.scaleFactor = finalScale;

    updateMovementConstraints();
    centerImage();
    appState.uploadedImage.setCoords();
    updatePositionInfo();
    
    const slider = document.getElementById("zoomSlider");
    if (slider) {
      slider.value = String(Math.round(appState.zoom * 100));
      updateSliderBackground(slider);
    }
    
    updateZoomLabel();
    canvas.requestRenderAll();
  } catch (error) {
    console.error("Error in updateZoom:", error);
  }
}

function updateZoomLabel() {
  const zoomLabel = document.getElementById("zoomLabel");
  if (zoomLabel) {
    zoomLabel.textContent = `${Math.round(appState.zoom * 100)}%`;
  }
}

function syncZoomSlider() {
  const slider = document.getElementById("zoomSlider");
  if (!slider || !appState.uploadedImage) return;

  try {
    // Calculate current zoom based on image scale
    const baseScale = getBaseScale();
    
    if (baseScale <= 0 || !isFinite(baseScale)) {
      console.warn("Invalid base scale:", baseScale);
      return;
    }
    
    const currentZoom = appState.uploadedImage.scaleX / baseScale;
    
    // Update appState.zoom with proper bounds
    appState.zoom = Math.max(
      appState.minZoom, 
      Math.min(appState.maxZoom, currentZoom)
    );
    
    // Update slider
    slider.min = String(appState.minZoom * 100);
    slider.max = String(appState.maxZoom * 100);
    slider.value = String(Math.round(appState.zoom * 100));
    
    updateSliderBackground(slider);
    updateZoomLabel();
  } catch (error) {
    console.error("Error in syncZoomSlider:", error);
  }
}

function handleZoomSlider(slider) {
  if (!appState.uploadedImage) return;
  
  try {
    
    const zoomValue = parseInt(slider.value, 10) / 100;
    
    const baseScale = getBaseScale();
    const currentZoom = appState.uploadedImage.scaleX / baseScale;
    
    const currentDpi = Number((appState.dpi || 0).toFixed(2));
    if (currentDpi < 35 && zoomValue > currentZoom) {
      slider.value = String(Math.round(currentZoom * 100));
      updateSliderBackground(slider);
      return;
    }
    
    updateZoom(zoomValue);
    updateSliderBackground(slider);
  } catch (error) {
    console.error("Error in handleZoomSlider:", error);
  }
}
function setZoomToCover() {
  if (!appState.uploadedImage) return;
  
  const img = appState.uploadedImage;
  const canvasWidth = appState.selectedWidth;
  const canvasHeight = appState.selectedHeight;
  
  // Calculate cover scale (fills the frame)
  const scaleX = canvasWidth / img.width;
  const scaleY = canvasHeight / img.height;
  const coverScale = Math.max(scaleX, scaleY);
  
  // Calculate zoom level based on cover scale
  const baseScale = getBaseScale();
  const coverZoom = coverScale / baseScale;
  
  // Apply zoom
  updateZoom(coverZoom);
}


function setZoomToFit() {
  if (!appState.uploadedImage) return;
  
  const img = appState.uploadedImage;
  const canvasWidth = appState.selectedWidth;
  const canvasHeight = appState.selectedHeight;
  
  // Calculate fit scale (fits within frame)
  const scaleX = canvasWidth / img.width;
  const scaleY = canvasHeight / img.height;
  const fitScale = Math.min(scaleX, scaleY);
  
  // Calculate zoom level based on fit scale
  const baseScale = getBaseScale();
  const fitZoom = fitScale / baseScale;
  
  // Apply zoom (100% = fit to frame)
  updateZoom(fitZoom);
}


function zoomIn() {
  if (!appState.uploadedImage) return;
  
  const newZoom = appState.zoom * 1.1;
  
  // Check DPI before applying zoom
  const currentDpi = Number((appState.dpi || 0).toFixed(2));
  if (currentDpi < 35) {
    return;
  }
  
  updateZoom(newZoom);
}

function zoomOut() {
  if (!appState.uploadedImage) return;
  
  // Decrease zoom by 10%
  const newZoom = appState.zoom * 0.9;
  updateZoom(newZoom);
}

function resetZoom() {
  // Reset to 100% zoom (fit to frame)
  updateZoom(1.0);
}

handleZoomSlider(slider);

slider.addEventListener("input", () => handleZoomSlider(slider));

// zoomInBtn.addEventListener("click", () => updateZoom(appState.zoom + 1));
// zoomOutBtn.addEventListener("click", () => updateZoom(appState.zoom - 1));

// ===========================================
// PINCH TO ZOOM FUNCTIONALITY FOR MOBILE
// ===========================================
// Variables for pinch zoom
let initialDistance = 0;
let initialZoom = 1;
let lastCenter = { x: 0, y: 0 };
let isPinching = false;
let lastTouchTime = 0;

// Function to calculate distance between two touch points
function getTouchDistance(touch1, touch2) {
  const dx = touch2.clientX - touch1.clientX;
  const dy = touch2.clientY - touch1.clientY;
  return Math.sqrt(dx * dx + dy * dy);
}

// Function to calculate center point between two touches
function getTouchCenter(touch1, touch2) {
  return {
    x: (touch1.clientX + touch2.clientX) / 2,
    y: (touch1.clientY + touch2.clientY) / 2
  };
}

// Convert screen coordinates to canvas coordinates
function screenToCanvas(x, y) {
  const canvasRect = canvas.getElement().getBoundingClientRect();
  const zoom = canvas.getZoom();
  return {
    x: (x - canvasRect.left) / zoom,
    y: (y - canvasRect.top) / zoom
  };
}

// Touch start event
canvas.wrapperEl.addEventListener('touchstart', function(e) {
  if (e.touches.length === 2 && appState.uploadedImage) {
    e.preventDefault();
    e.stopPropagation();
    
    const touch1 = e.touches[0];
    const touch2 = e.touches[1];
    
    initialDistance = getTouchDistance(touch1, touch2);
    initialZoom = appState.scaleFactor || 1;
    lastCenter = getTouchCenter(touch1, touch2);
    isPinching = true;
    
    // Store the timestamp to prevent double-tap zoom
    lastTouchTime = Date.now();
  }
}, { passive: false });

// Touch move event
canvas.wrapperEl.addEventListener('touchmove', function(e) {
  if (e.touches.length === 2 && appState.uploadedImage && isPinching) {
    e.preventDefault();
    e.stopPropagation();
    
    const touch1 = e.touches[0];
    const touch2 = e.touches[1];
    
    const currentDistance = getTouchDistance(touch1, touch2);
    const currentCenter = getTouchCenter(touch1, touch2);
    
    // Calculate zoom factor
    const zoomFactor = currentDistance / initialDistance;
    const newScale = initialZoom * zoomFactor;
    
    // Apply constraints to zoom
    const minScale = 0.01;
    const maxScale = 10;
    const clampedScale = Math.max(minScale, Math.min(maxScale, newScale));
    
    // Get canvas center in screen coordinates
    const canvasRect = canvas.getElement().getBoundingClientRect();
    const canvasCenterX = canvasRect.left + canvasRect.width / 2;
    const canvasCenterY = canvasRect.top + canvasRect.height / 2;
    
    // Calculate translation (panning during pinch)
    const deltaX = currentCenter.x - lastCenter.x;
    const deltaY = currentCenter.y - lastCenter.y;
    
    // Apply zoom with pivot at touch center
    const oldScale = appState.scaleFactor;
    appState.scaleFactor = clampedScale;
    
    // Calculate the scale change
    const scaleChange = clampedScale / oldScale;
    
    // Update the image scale
    if (appState.uploadedImage) {
      const img = appState.uploadedImage;
      
      // Convert touch center to canvas coordinates relative to image
      const canvasCoords = screenToCanvas(lastCenter.x, lastCenter.y);
      
      // Get current image position and dimensions
      const imgLeft = img.left;
      const imgTop = img.top;
      const imgWidth = img.getScaledWidth();
      const imgHeight = img.getScaledHeight();
      
      // Calculate new position to keep the pinch center point fixed
      const newLeft = canvasCoords.x - (canvasCoords.x - imgLeft) * scaleChange;
      const newTop = canvasCoords.y - (canvasCoords.y - imgTop) * scaleChange;
      
      // Apply new scale and position
      img.scaleX = clampedScale;
      img.scaleY = clampedScale;
      img.left = newLeft;
      img.top = newTop;
      
      // Also apply additional panning from finger movement
      img.left += deltaX / canvas.getZoom();
      img.top += deltaY / canvas.getZoom();
      
      img.setCoords();
    }
    
    // Update center for next move
    lastCenter = currentCenter;
    
    // Update everything
    updateMovementConstraints();
    updatePositionInfo();
    syncZoomSlider();
    canvas.requestRenderAll();
  } else if (e.touches.length === 1 && appState.uploadedImage && !isPinching) {
    // Allow single finger panning (fabric.js will handle this)
    // We just need to update position info
    requestAnimationFrame(() => {
      updatePositionInfo();
    });
  }
}, { passive: false });

// Touch end event
canvas.wrapperEl.addEventListener('touchend', function(e) {
  if (isPinching) {
    isPinching = false;
    
    // Reset variables
    initialDistance = 0;
    initialZoom = 1;
    lastCenter = { x: 0, y: 0 };
    
    // Sync slider with current zoom
    syncZoomSlider();
    canvas.requestRenderAll();
  }
  
  // Handle double tap for zoom reset
  const currentTime = Date.now();
  const timeDiff = currentTime - lastTouchTime;
  
  // if (timeDiff < 300 && e.touches.length === 0 && e.changedTouches.length === 1) {
  //   // Double tap detected - reset to fit
  //   if (appState.uploadedImage) {
  //     fitImageToFrame(true);
  //   }
  // }
  
  lastTouchTime = currentTime;
});

// Prevent default touch actions on canvas
canvas.wrapperEl.style.touchAction = 'none';
canvas.wrapperEl.style.webkitUserSelect = 'none';
canvas.wrapperEl.style.userSelect = 'none';

// Also add touch event listeners to the canvas element itself
canvas.getElement().addEventListener('touchstart', function(e) {
  if (e.touches.length === 2) {
    e.preventDefault();
  }
}, { passive: false });

canvas.getElement().addEventListener('touchmove', function(e) {
  if (e.touches.length === 2) {
    e.preventDefault();
  }
}, { passive: false });

// Add pinch zoom indicator (optional visual feedback)
function showPinchFeedback() {
  const feedback = document.createElement('div');
  feedback.style.cssText = `
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: rgba(0,0,0,0.7);
    color: white;
    padding: 10px 20px;
    border-radius: 20px;
    font-size: 14px;
    z-index: 10000;
    pointer-events: none;
    transition: opacity 0.3s;
  `;
  feedback.textContent = 'Pinch to zoom';
  document.body.appendChild(feedback);
  
  setTimeout(() => {
    feedback.style.opacity = '0';
    setTimeout(() => {
      document.body.removeChild(feedback);
    }, 300);
  }, 1500);
}

// Show pinch hint on mobile devices on first interaction
if ('ontouchstart' in window && window.innerWidth < 768) {
  let pinchHintShown = localStorage.getItem('pinchHintShown');
  if (!pinchHintShown) {
    setTimeout(() => {
      if (appState.uploadedImage) {
        showPinchFeedback();
        localStorage.setItem('pinchHintShown', 'true');
      }
    }, 2000);
  }
}


window.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const toolParam = params.get("tool");
  const syncmodeparam = params.get("syncMode");

  const firstSelected = document.querySelector("#frameSizeOptions input[name=\"frameSize\"]:checked") || document.querySelector("#frameSizeOptions input[name=\"frameSize\"]");

  if (firstSelected) {
    const [width, height] = firstSelected.getAttribute("data-size").split("x").map(Number);
    appState.selectedWidth = width;
    appState.selectedHeight = height;
    updateFrameFromPixels(appState.selectedWidth, appState.selectedHeight);
  }

  if (syncmodeparam === "select-pdp" || syncmodeparam === "select-print" ||  syncmodeparam === "pdp-select" || syncmodeparam === "pdp-img" ) {
    let sessionImageData1;
let shouldDisableSizes = false;
let pdpSelectTag;
    if (syncmodeparam === "select-pdp") {
      sessionImageData1 = getLocalStorage1Day("pdp-select-img");  
      pdpSelectTag = getLocalStorage1Day("select-tags");  
    } else if (syncmodeparam === "select-print") {
      sessionImageData1 = getLocalStorage1Day("select-print-image");
      pdpSelectTag = getLocalStorage1Day("select-tags");  
    } else if (syncmodeparam === "pdp-img") {
      sessionImageData1 = getLocalStorage1Day("pdpUploadedImage");
    }  else if(syncmodeparam === "pdp-select") {
      sessionImageData1 = getLocalStorage1Day("frame-select-img");
       pdpSelectTag = getLocalStorage1Day("select-tags");  
    }

    if (pdpSelectTag) {
      try {
        const tags = JSON.parse(pdpSelectTag);
        shouldDisableSizes = tags.includes("style-image") || tags.includes("edit-image");
      } catch (e) {
        console.error(e);
      }
    }

    const disableFrameSizes = [
      '30″×40″',
      '20″×60″',
      '32″×48″',
      '40″×60″',
      '20″×40″',
      '24″×48″',
      '32″×32″',
      '36″×36″',
      '37″×37″'
    ];

   
if (shouldDisableSizes) {

  document.querySelectorAll('#frameSizeOptions input[name="frameSize"]').forEach(input => {

    const frameSize = input.getAttribute("data-frmsize");

    if (disableFrameSizes.includes(frameSize)) {

      input.disabled = true;

      const label = input.closest(".frame-size-btn");

      if (label) {
        label.style.pointerEvents = "none";
        label.style.opacity = "0.5";
        label.style.cursor = "not-allowed";
      }

    }

  });

}
    if (sessionImageData1) {
      galleryWrapper.style.display = "none";
      uploadInputwrap.style.display = "none";
      customForm.style.display = "block";
      requestCanvasZoomRecalc();

      const mainImgWrap = document.querySelector(".main-img-wrap");
      if (mainImgWrap) {
        mainImgWrap.setAttribute("data-main-img", sessionImageData1);
      }

      const tempImg = new Image();
      tempImg.onload = function() {

        const imgfileWElement = document.getElementById("img-file-w");
        const imgfileHElement = document.getElementById("img-file-h");

        if (imgfileWElement) imgfileWElement.textContent = tempImg.width;
        if (imgfileHElement) imgfileHElement.textContent = tempImg.height;

        fabric.Image.fromURL(sessionImageData1, function(img) {
          cleanupCropSelection();
          appState.uploadedImage = img;
          appState.cropState = { isCropped: false, backup: null, isSelecting: false, selectionRect: null };
          updateCropButtonState();
          appState.uploadedImage.set({
            selectable: true,
            hasBorders: false,
            hasControls: false,
            lockRotation: true,
            lockScalingFlip: true,
            lockUniScaling: true,
            originX: "center",
            originY: "center",
            clipPath: appState.clipPath,
          });

          canvas.add(appState.uploadedImage);
          setMovementConstraints(); // Add this
          canvas.setActiveObject(appState.uploadedImage);
          canvas.moveTo(appState.uploadedImage, 2);
          FitFrontFrame();;
        });
        document.querySelectorAll(".image-conform-btn").forEach(div => {
          div.style.pointerEvents = "auto";
          div.style.opacity = "1";
        });
      };
      tempImg.src = sessionImageData1;
    }
  }
});


document.addEventListener("DOMContentLoaded", function () {
  function updateVariantId() {
    const size = document.querySelector('input[name="frameSize"]:checked')?.value;
    if (!size) return;

    const variant = window.productVariants?.find(
      (v) => v.option1 === size
    );

    if (!variant) {
      console.warn("No variant matched the selected size:", size);
      return;
    }


    const variantInput = document.querySelector('input[name="id"]');
    if (variantInput) variantInput.value = variant.id;

    const variantInputSize = document.querySelector('input[name="properties[_pdp-size]"]');
    if (variantInputSize) variantInputSize.value = variant.option1;

    const variantInputSku = document.querySelector('input[name="properties[_pdp-variant-id]"]');
    if (variantInputSku) variantInputSku.value = variant.sku;


    let numericPrice = null;
    let numericCmpPrice = null;
    if (typeof variant.price === "number") {
      numericPrice = variant.price / 100;
    } else if (variant.price?.amount) {
      numericPrice = parseFloat(variant.price.amount);
    } else if (variant.priceV2?.amount) {
      numericPrice = parseFloat(variant.priceV2.amount);
    }

    let finalPrice = numericPrice;
    if (Number.isFinite(numericPrice) && window.isPremiumCustomer === true) {
      finalPrice = numericPrice * 0.9; // 10% OFF
    }


    const priceElement = document.querySelector("#price-sale-text");
    if (priceElement) {
      priceElement.textContent = Number.isFinite(finalPrice)
        ? `$${finalPrice.toFixed(2)}`
        : "";
    }

       const priceElement1 = document.querySelector(".main-price");
    if (priceElement1) {
      priceElement1.textContent = Number.isFinite(finalPrice)
        ? `$${finalPrice.toFixed(2)}`
        : "";
    }
   
    if (typeof variant.compare_at_price === "number") {
      numericCmpPrice = variant.compare_at_price / 100;
    } else if (variant.compare_at_price?.amount) {
      numericCmpPrice = parseFloat(variant.compare_at_price.amount);
    } else if (variant.compare_at_priceV2?.amount) {
      numericCmpPrice = parseFloat(variant.compare_at_priceV2.amount);
    }

    const cmppriceElement = document.querySelector("#compare-price-text");
    if (cmppriceElement) {
      cmppriceElement.textContent = Number.isFinite(numericCmpPrice)
        ? `$${numericCmpPrice.toFixed(2)}`
        : "";
    }
     const cmppriceElement1 = document.querySelector(".compare-price");
    if (cmppriceElement1) {
      cmppriceElement1.textContent = Number.isFinite(numericCmpPrice)
        ? `$${numericCmpPrice.toFixed(2)}`
        : "";
    }

    const savePrElement = document.querySelector("#save-pr-text");
    if (savePrElement) {
      if (
        Number.isFinite(finalPrice) &&
        Number.isFinite(numericCmpPrice) &&
        numericCmpPrice > finalPrice
      ) {
        const discountPercent = Math.round(
          ((numericCmpPrice - finalPrice) / numericCmpPrice) * 100
        );
        savePrElement.textContent = `${discountPercent}%`;
        savePrElement.style.display = "";
      } else {
        savePrElement.textContent = "";
        savePrElement.style.display = "none";
      }
    }
     const savePrElement1 = document.querySelector(".save-percentage");
    if (savePrElement1) {
      if (
        Number.isFinite(finalPrice) &&
        Number.isFinite(numericCmpPrice) &&
        numericCmpPrice > finalPrice
      ) {
        const discountPercent = Math.round(
          ((numericCmpPrice - finalPrice) / numericCmpPrice) * 100
        );
        savePrElement1.textContent = `Save ${discountPercent}%`;
        savePrElement1.style.display = "";
      } else {
        savePrElement1.textContent = "";
        savePrElement1.style.display = "none";
      }
    }


    const productImage = document.querySelector(".image-magnify-lightbox");
    if (productImage && variant.image) {
      const imageUrl =
        typeof variant.image === "string"
          ? variant.image
          : variant.image.src;

      productImage.src = imageUrl;

      const widths = [246, 493, 600, 713, 823, 990, 1100, 1206, 1346, 1426, 1646, 1946];
      productImage.srcset = widths
        .map((w) => `${imageUrl}?width=${w} ${w}w`)
        .join(", ");

      productImage.alt = variant.image.alt || variant.option1;
    }

    if (typeof logAllAddedElements === "function") {
      logAllAddedElements();
    }
  }

  document
    .querySelectorAll('input[name="frameSize"], input[name="frameColor"]')
    .forEach((input) => {
      input.addEventListener("change", updateVariantId);
    });

  updateVariantId();
});


document.querySelectorAll(".image-conform-btn").forEach(btn => {
  btn.addEventListener("click", function (e) {
    sendMainImageToAPI(e);
  });
});

async function sendMainImageToAPI(e) {

  const edgeTypeInput = document.getElementById("final-image-type-data");
  const edgeType = edgeTypeInput ? edgeTypeInput.value : "FitToEdge";


  const finalpopup = document.querySelector(".finalize-image-popup");
  if (finalpopup) finalpopup.style.display = "flex";

  const finalpopup1 = document.querySelector("#is-first");
  if (finalpopup1) finalpopup1.style.display = "block";

  const finalpopup2 = document.querySelector("#is-second");
  if (finalpopup2) finalpopup2.style.display = "none";

  const btn = e.currentTarget;
  btn.textContent = "Processing...";
  btn.disabled = true;

  try {
    if (edgeType === "FitToEdge") {

      const mainImgWrap = document.querySelector(".main-img-wrap");
      if (!mainImgWrap) throw new Error("No .main-img-wrap element found");

      const imageData = mainImgWrap.getAttribute("data-main-img");
      if (!imageData) throw new Error("No image data found");

      function base64ToBlob(base64) {
        const byteString = atob(base64.split(",")[1]);
        const mimeString = base64.split(",")[0].split(":")[1].split(";")[0];
        const ab = new ArrayBuffer(byteString.length);
        const ia = new Uint8Array(ab);
        for (let i = 0; i < byteString.length; i++) ia[i] = byteString.charCodeAt(i);
        return new Blob([ab], { type: mimeString });
      }

      const formData = new FormData();
      const userId = window.shopifyCustomerId || "guest";
      const sessionId = getLocalStorage1Day("sessionId") || "none";

      if (imageData.startsWith("http") || imageData.startsWith("//")) {
        formData.append("imageUrl", imageData);
      } else if (imageData.startsWith("data:image/")) {
        const imageBlob = base64ToBlob(imageData);
        formData.append("file", imageBlob, "uploaded-image.jpeg");
      } else {
        throw new Error("Invalid image data format");
      }

      formData.append("customerId", userId);
      formData.append("sessionId", sessionId);

      const response = await fetch(`${window.Prompt2Prints.apiBase}/upload-image`, {
        method: "POST",
              headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
        body: formData,
      });
      const data = await response.json();

        const imageUpscale = document.querySelector('input[name="properties[_pdp-allow-upscale]"]');
const imageUpscaletag = document.querySelector('input[name="properties[_pdp-img-tag]"]');

if (!imageUpscale || !imageUpscaletag) {
  console.warn("Upscale inputs not found");
  return;
}

const flag = (data.flag || "").toLowerCase();

if (flag === "standard") {
  imageUpscale.value = "true";
  imageUpscaletag.value = "Standard";
} 
else if (flag === "professional") {
  imageUpscale.value = "false";
  imageUpscaletag.value = "Professional";
} 
else {
  imageUpscale.value = "";
  imageUpscaletag.value = "";
}

// Optional: also update attribute for Shopify forms
imageUpscale.setAttribute("value", imageUpscale.value);
imageUpscaletag.setAttribute("value", imageUpscaletag.value);

const cvswElement = parseFloat(document.getElementById("cvs-w")?.textContent) || 0;
const cvswFinalElement = appState.finalw || 0;
const cvshFinalElement = appState.finalh || 0;
const cvstElement = appState.finalt || 0;
const cvslElement = appState.finall || 0;
              const cvshElement = parseFloat(document.getElementById("cvs-h")?.textContent) || 0;
              const hiddenimg = document.getElementById("frame-img-position");
                 const orientationRadio = document.querySelector('input[name="orientation"]:checked');
    const orientation = orientationRadio ? orientationRadio.value : "portrait";
    if(orientation == "portrait"){
        if (hiddenimg) {
                hiddenimg.value = JSON.stringify({
                  area_width: cvswElement,
                  area_height: cvshElement,
                  width: cvswFinalElement,
                  height: cvshFinalElement,
                  top: cvstElement,
                  left: cvslElement,
                });
              }
    }
    else if(orientation == "landscape"){
      if (hiddenimg) {
                hiddenimg.value = JSON.stringify({
                  area_width: cvswElement,
                  area_height: cvshElement,
                  width: cvswFinalElement,
                  height: cvshFinalElement,
                   top: cvstElement,
                  left: cvslElement,
                });
              }
    }
      const hiddenInput = document.getElementById("final-image-data");
      if (hiddenInput && data.cloudfrontLink) {
        hiddenInput.value = data.cloudfrontLink;
      }

      await exportFullDivAsImage(userId, sessionId);

      // These will only run after exportFullDivAsImage is completely finished
      if (finalpopup1) finalpopup1.style.display = "none";
      if (finalpopup2) finalpopup2.style.display = "block";

      btn.textContent = "Submitted!";
      return;
    }

    // =========================================
    // BLACK WRAP FLOW
    // =========================================
    if (edgeType === "BlackWrap") {
      await generateCanvasWithBlackEdge(); 
      // These will only run after generateCanvasWithBlackEdge is completely finished
      if (finalpopup1) finalpopup1.style.display = "none";
      if (finalpopup2) finalpopup2.style.display = "block";

      btn.textContent = "Submitted!";
      return;
    }

    if (edgeType === "MirrorWrap") {
      await generateCanvasWithMirrorEdge();

      if (finalpopup1) finalpopup1.style.display = "none";
      if (finalpopup2) finalpopup2.style.display = "block";

      btn.textContent = "Submitted!";
      return;
    }

    // =========================================
    // WHITE WRAP FLOW
    // =========================================
    if (edgeType === "WhiteWrap") {
      await generateCanvasWithWhiteEdge(); // This will now properly wait
     
      
      // These will only run after generateCanvasWithWhiteEdge is completely finished
      if (finalpopup1) finalpopup1.style.display = "none";
      if (finalpopup2) finalpopup2.style.display = "block";

      btn.textContent = "Submitted!";
      return;
    }
  } catch (error) {
    console.error("ERROR in sendMainImageToAPI:", error);
    btn.textContent = "Failed. Try again";
  } finally {
    btn.disabled = false;
  }
}
async function urlToBase64(url) {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.crossOrigin = "https://prompt2prints.com";
    img.onload = () => {
      const canvasEl = document.createElement("canvas");
      canvasEl.width = img.width;
      canvasEl.height = img.height;
      const ctx = canvasEl.getContext("2d");
      ctx.drawImage(img, 0, 0);
      resolve(canvasEl.toDataURL("image/jpeg"));
    };
    img.onerror = reject;
    img.src = url;
  });
}

window.addedElements = [];

window.logAllAddedElements = function() {
  window.addedElements.forEach((el, index) => {
    // Log elements if needed
  });
};

window.removeSelectedElements = function(indices) {
    indices.sort((a, b) => b - a);

    indices.forEach((i) => {
        if (window.addedElements[i]) {
            canvas.remove(window.addedElements[i]);
            window.addedElements.splice(i, 1);
        }
    });
};


async function reloadImageAsBase64(img) {

  const src = img._element.src;
  const left = img.left;
  const top = img.top;
  const scaleX = img.scaleX;
  const scaleY = img.scaleY;
  const angle = img.angle;
  const originX = img.originX;
  const originY = img.originY;

  const base64 = await urlToBase64(src);

  return new Promise((resolve) => {
    fabric.Image.fromURL(base64, (newImg) => {
      newImg.set({ left, top, scaleX, scaleY, angle, originX, originY });

      // 🔴 REMOVE CENTER GUIDE LINES
      canvas.getObjects('line').forEach((obj) => {
        if (obj.stroke === 'red' && obj.opacity === 0.5 ) {
          canvas.remove(obj);
        }
        else if(obj.name === 'centerLine'){
           canvas.remove(obj);
        }
      });

      canvas.remove(img);
      canvas.setBackgroundColor("#ffffff", canvas.renderAll.bind(canvas));

      canvas.add(newImg);
      window.addedElements.push(newImg);

      // ---------------- INNER PADDING LOGIC ----------------
      let innerPadding;
      const size = `${appState.originalWidth}x${appState.originalHeight}`;

      if (window.innerWidth < 680) {
      if (size === "900x900") {
        innerPadding = 150 / 4.5;
      } else if (size === "1100x1100") {
        innerPadding = 150 / 5.5;
      } else if (size === "1100x1300") {
        innerPadding = 150 / 6.5;
      } else if (size === "1100x1500") {
        innerPadding = 150 / 7.5;
      } else if (size === "1200x1500") {
        innerPadding = 150 / 7.5;
      } else if (size === "1300x1300") {
        innerPadding = 150 / 6.5;
      } else if (size === "1300x2300") {
        innerPadding = 150 / 11.5;
      } else if (size === "100x1700") {
        innerPadding = 150 / 8.5;
      } else if (size === "1800x1800") {
        innerPadding = 300 / 9;
      } else if (size === "1800x2200") {
        innerPadding = 300 / 11;
      } else if (size === "1500x2100") {
        innerPadding = 150 / 10.5;
      } else if (size === "1500x2700") {
        innerPadding = 150 / 13.5;
      } else if (size === "1500x3900") {
        innerPadding = 150 / 19.5;
      } else if (size === "1700x1700") {
        innerPadding = 150 / 8.5;
      } else if (size === "2200x2200") {
        innerPadding = 300 / 11;
      } else if (size === "2200x2600") {
        innerPadding = 300 / 13;
      } else if (size === "1900x2700") {
        innerPadding = 150 / 13.5;
      } else if (size === "1900x3500") {
        innerPadding = 150 / 17.5;
      } else if (size === "1900x5100") {
        innerPadding = 150 / 25.5;
      } else if (size === "2100x2100") {
        innerPadding = 150 / 10.5;
      } else if (size === "2400x3000") {
        innerPadding = 300 / 15;
      } else if (size === "2100x2900") {
        innerPadding = 150 / 14.5;
      } else if (size === "2300x2300") {
        innerPadding = 150 / 11.5;
      } else if (size === "2300x2700") {
        innerPadding = 150 / 13.5;
      } else if (size === "2300x3100") {
        innerPadding = 150 / 15.5;
      } else if (size === "2300x3300") {
        innerPadding = 150 / 16.5;
      } else if (size === "2300x4300") {
        innerPadding = 150 / 21.5;
      } else if (size === "2300x6300") {
        innerPadding = 150 / 31.5;
      } else if (size === "2700x2700") {
        innerPadding = 150 / 13.5;
      } else if (size === "2700x3300") {
        innerPadding = 150 / 16.5;
      } else if (size === "2700x3500") {
        innerPadding = 150 / 17.5;
      } else if (size === "3000x4200") {
        innerPadding = 300 / 21;
      } else if (size === "2700x5100") {
        innerPadding = 150 / 25.5;
      } else if (size === "2900x2900") {
        innerPadding = 150 / 14.5;
      } else if (size === "2900x4300") {
        innerPadding = 150 / 21.5;
      } else if (size === "3100x3100") {
        innerPadding = 150 / 15.5;
      } else if (size === "3100x4300") {
        innerPadding = 150 / 21.5;
      } else if (size === "3300x3300") {
        innerPadding = 150 / 16.5;
      } else if (size === "3300x4300") {
        innerPadding = 150 / 21.5;
      } else if (size === "3300x6300") {
        innerPadding = 150 / 31.5;
      } else if (size === "3500x3500") {
        innerPadding = 150 / 17.5;
      } else if (size === "3500x5100") {
        innerPadding = 150 / 25.5;
      } else if (size === "3900x3900") {
        innerPadding = 150 / 19.5;
      } else if (size === "4000x4000") {
        innerPadding = 150 / 20;
      } else if (size === "4300x5800") {
        innerPadding = 150 / 29;
      } else if (size === "4300x6300") {
        innerPadding = 150 / 31.5;
      } else {
        innerPadding = null;
      }
} else {

 if (size === "900x900") {
        innerPadding = 150 / 2.25;
      } else if (size === "1100x1100") {
        innerPadding = 150 / 2.75;
      } else if (size === "1100x1300") {
        innerPadding = 150 / 3.25;
      } else if (size === "1100x1500") {
        innerPadding = 150 / 3.75;
      } else if (size === "1200x1500") {
        innerPadding = 150 / 3.75;
      } else if (size === "1300x1300") {
        innerPadding = 150 / 3.25;
      } else if (size === "1300x2300") {
        innerPadding = 150 / 5.75;
      } else if (size === "1400x1700") {
        innerPadding = 150 / 4.25;
      } else if (size === "1800x1800") {
        innerPadding = 300 / 4.5;
      } else if (size === "1800x2200") {
        innerPadding = 300 / 5.5;
      } else if (size === "1500x2100") {
        innerPadding = 150 / 5.25;
      } else if (size === "1500x2700") {
        innerPadding = 150 / 6.75;
      } else if (size === "1500x3900") {
        innerPadding = 150 / 9.75;
      } else if (size === "1700x1700") {
        innerPadding = 150 / 4.25;
      } else if (size === "2200x2200") {
        innerPadding = 300 / 5.5;
      } else if (size === "2200x2600") {
        innerPadding = 300 / 6.5;
      } else if (size === "1900x2700") {
        innerPadding = 150 / 6.75;
      } else if (size === "1900x3500") {
        innerPadding = 150 / 8.75;
      } else if (size === "1900x5100") {
        innerPadding = 150 / 12.75;
      } else if (size === "2100x2100") {
        innerPadding = 150 / 5.25;
      } else if (size === "2400x3000") {
        innerPadding = 300 / 7.5;
      } else if (size === "2100x2900") {
        innerPadding = 150 / 7.25;
      } else if (size === "2300x2300") {
        innerPadding = 150 / 5.75;
      } else if (size === "2300x2700") {
        innerPadding = 150 / 6.75;
      } else if (size === "2300x3100") {
        innerPadding = 150 / 7.75;
      } else if (size === "2300x3300") {
        innerPadding = 150 / 8.25;
      } else if (size === "2300x4300") {
        innerPadding = 150 / 10.75;
      } else if (size === "2300x6300") {
        innerPadding = 150 / 15.75;
      } else if (size === "2700x2700") {
        innerPadding = 150 / 6.75;
      } else if (size === "2700x3300") {
        innerPadding = 150 / 8.25;
      } else if (size === "2700x3500") {
        innerPadding = 150 / 8.75;
      } else if (size === "3000x4200") {
        innerPadding = 300 / 10.5;
      } else if (size === "2700x5100") {
        innerPadding = 150 / 12.75;
      } else if (size === "2900x2900") {
        innerPadding = 150 / 7.25;
      } else if (size === "2900x4300") {
        innerPadding = 150 / 10.75;
      } else if (size === "3100x3100") {
        innerPadding = 150 / 7.75;
      } else if (size === "3100x4300") {
        innerPadding = 150 / 10.75;
      } else if (size === "3300x3300") {
        innerPadding = 150 / 8.25;
      } else if (size === "3300x4300") {
        innerPadding = 150 / 10.75;
      } else if (size === "3300x6300") {
        innerPadding = 150 / 15.75;
      } else if (size === "3500x3500") {
        innerPadding = 150 / 8.75;
      } else if (size === "3500x5100") {
        innerPadding = 150 / 12.75;
      } else if (size === "3900x3900") {
        innerPadding = 150 / 9.75;
      } else if (size === "4000x4000") {
        innerPadding = 150 / 10;
      } else if (size === "4300x5800") {
        innerPadding = 150 / 14.5;
      } else if (size === "4300x6300") {
        innerPadding = 150 / 15.75;
      } else {
        innerPadding = null;
      }
}
      const borderSize = innerPadding;

      const frmcolor1 = "rgba(0, 0, 0, 0.4)";
// Existing border
const border = new fabric.Rect({
  top: 0,
  left: 0,
  width: appState.selectedWidth - borderSize,
  height: appState.selectedHeight - borderSize,
  fill: 'transparent',
  stroke: frmcolor1,
  strokeWidth: borderSize,
  selectable: false,
  evented: false
});

canvas.add(border);
canvas.bringToFront(border);
window.addedElements.push(border);

// ----------------- ADD DOTTED LINE INSIDE -----------------
const dotPadding = borderSize; // distance from border
const dottedBorder = new fabric.Rect({
  top: dotPadding,
  left: dotPadding,
  width: appState.selectedWidth - (borderSize * 2) - 1,
  height: appState.selectedHeight - (borderSize * 2) - 1 ,
  fill: 'transparent',
  stroke: 'rgba(0,0,0,0.4)', // you can change color
  strokeWidth: 1,
  selectable: false,
  evented: false,
  strokeDashArray: [5, 5] // 5px line, 5px gap
});

canvas.add(dottedBorder);
canvas.bringToFront(dottedBorder);
window.addedElements.push(dottedBorder);
      resolve(newImg);
      logAllAddedElements();

    }, { crossOrigin: "anonymous" });
  });
}



async function exportFullDivAsImage(customerId, sessionId) {
  const parentDiv = document.querySelector(".back-image");
  if (!parentDiv) {
    console.error("No element with class .back-image found");
    return;
  }

  if (typeof canvas === "undefined") {
    console.error("Fabric.js canvas not defined");
    return;
  }

  canvas.discardActiveObject();
  canvas.getObjects().forEach(obj => obj.set({
    selectable: false,
    evented: false
  }));

  canvas.renderAll();

  try {
    const images = canvas.getObjects("image");
    await Promise.all(images.map(img => reloadImageAsBase64(img)));
    

    // 1️⃣ Export canvas to data URL
    const dataURL = canvas.toDataURL({
      format: "jpeg",
      multiplier: 2,
    });
    // const paddedDataURL = await addPaddingToDataURL(dataURL, 0);

    const res = await fetch(dataURL);
    const blob = await res.blob();

    const formData = new FormData();
    formData.append("file", blob, "full-div-image.jpeg");
    formData.append("customerId", customerId);
    formData.append("sessionId", sessionId);
    formData.append("thumbnailWidth", "200");

    const response = await fetch(`${window.Prompt2Prints.apiBase}/image-thumbnail`, {
      method: "POST",
              headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
      body: formData,
    });

    const data = await response.json();

    const hiddenInput = document.getElementById("preview-image-data");
    if (hiddenInput && data.original?.cloudfrontUrl) hiddenInput.value = data.original.cloudfrontUrl;

    const hiddenInput1 = document.getElementById("preview-thumb-image-data");
    if (hiddenInput1 && data.thumbnail?.cloudfrontUrl) hiddenInput1.value = data.thumbnail.cloudfrontUrl;

    // Optional: display padded image in .full-content
    let fullContentDiv = document.querySelector(".full-content");
    if (!fullContentDiv) {
      fullContentDiv = document.createElement("div");
      fullContentDiv.className = "full-content";
      document.body.appendChild(fullContentDiv);
    }
    fullContentDiv.innerHTML = "";
    const imgElement = document.createElement("img");
    imgElement.src = dataURL;
    fullContentDiv.appendChild(imgElement);
    removeSelectedElements([1, 2, 3]);

  } catch (err) {
    console.error("Error exporting full div:", err);
  } finally {
    canvas.getObjects().forEach(obj => obj.set({
      selectable: true,
      evented: true
    }));
    canvas.renderAll();
  }
}

// Helper function: add padding to a dataURL
function addPaddingToDataURL(dataURL, padding) {
  return new Promise((resolve) => {
    const img = new Image();
    img.src = dataURL;
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = img.width + padding * 2;
      canvas.height = img.height + padding * 2;
      const ctx = canvas.getContext("2d");

        ctx.fillStyle = "#000000";

      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Draw original image in center
      ctx.drawImage(img, padding, padding);

      resolve(canvas.toDataURL("image/jpeg"));
    };
  });
}


function captureImageTransform(image) {
  if (!image) return null;

  return {
    left: image.left,
    top: image.top,
    angle: image.angle,
    originX: image.originX || "left",
    originY: image.originY || "top",

    // ✅ visible size in canvas px
    visibleWidth: image.getScaledWidth(),
    visibleHeight: image.getScaledHeight()
  };
}


function applyImageTransform(image, transform) {
  if (!image || !transform) return;

  const scaleX = transform.visibleWidth / image.width;
  const scaleY = transform.visibleHeight / image.height;

  image.set({
    left: transform.left,
    top: transform.top,
    angle: transform.angle,
    originX: transform.originX,
    originY: transform.originY,
    scaleX,
    scaleY
  });

  image.setCoords();
}


async function upscaleAndFixDPI({
  sessionId = "none",
  customerId = "guest",
  dpi = null,
  printHeight = null,
  printWidth = null,
  imageUrl = null,
  file = null,
  callback = null 
}) {

  const savepopup = document.querySelector(".save-image-popup");
  const afterSavePopup = document.querySelector("#aftersavepopup");

  if (savepopup) savepopup.style.display = "flex";
  if (afterSavePopup) afterSavePopup.style.display = "none";

  const savepopuptitle = document.querySelector(".save-image-title");
  const savepopupicon = document.querySelector(".save-image-icon");
  const savepopuptext = document.querySelector(".save-image-text");

  savepopuptitle.textContent = "Boosting Image";
  savepopuptext.textContent = "Boosting resolution for maximum clarity";
  if (savepopupicon) savepopupicon.style.display = "flex";

  // 🔹 SAVE CURRENT IMAGE TRANSFORM
  const previousTransform = captureImageTransform(appState.uploadedImage);

  const imagefinalWidth = (appState.imageWidth * 300) / appState.dpi;
  const imagefinalHeight = (appState.imageheight * 300) / appState.dpi;

const imagesize = appState.uploadimgsize;
  const formData = new FormData();
  formData.append("sessionId", sessionId);
  formData.append("customerId", customerId);
  if (dpi) formData.append("dpi", dpi);
  if (printWidth) formData.append("printWidth", printWidth);
  if (printHeight) formData.append("printHeight", printHeight);
  formData.append("format", "jpeg");
  formData.append("faceEnhancement", "true");
  formData.append("finalWidth", imagefinalWidth);
  formData.append("finalHeight", imagefinalHeight);
const currentPageUrl = window.location.href; 
formData.append("page_url", currentPageUrl); 
  if (imageUrl) {
    formData.append("imageUrl", imageUrl);
  }

  if (file) {
    formData.append("file", file);
    formData.append("isDirectUpload", "true");
      formData.append("inputImageSizeMB", imagesize);
  }

  try {
    const response = await fetch(`${window.Prompt2Prints.apiBase}/boost-image`, {
      method: "POST",
              headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
      body: formData
    });
 if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    const result = await response.json();
      if (result?.error) {
      throw new Error(result.error);
    }

     const enhancedUrl = result?.enhanced;
    if (!enhancedUrl) {
      throw new Error("No enhanced URL returned");
    }

    const mainImgWrap = document.querySelector(".main-img-wrap");
    if (mainImgWrap) {
      mainImgWrap.setAttribute("data-main-img", enhancedUrl);
      mainImgWrap.innerHTML = `<img src="${enhancedUrl}" style="max-width:100%;">`;
    }

    fabric.Image.fromURL(enhancedUrl, async (img) => {

      // 🔹 CLEAR CANVAS SAFELY
      canvas.clear();
      canvas.setBackgroundColor("#ffffff", canvas.renderAll.bind(canvas));

      cleanupCropSelection();
      appState.uploadedImage = img;
      appState.cropState = { isCropped: false, backup: null, isSelecting: false, selectionRect: null };
      updateCropButtonState();
      appState.uploadedImage.set({
        selectable: true,
        hasBorders: false,
        hasControls: false,
        lockRotation: true,
        lockScalingFlip: true,
        lockUniScaling: true,
        originX: "center",
        originY: "center",
        clipPath: appState.clipPath || null
      });

      canvas.add(appState.uploadedImage);

      // 🔹 RESTORE EXACT SAME POSITION
      if (previousTransform) {
        applyImageTransform(appState.uploadedImage, previousTransform);
      } else {
        canvas.centerObject(appState.uploadedImage);
      }

      setMovementConstraints();
      canvas.setActiveObject(appState.uploadedImage);
      canvas.renderAll();

      // fitImageToFrame(true);

      document.getElementById("img-file-w").textContent =
        appState.uploadedImage.width || 0;
      document.getElementById("img-file-h").textContent =
        appState.uploadedImage.height || 0;

      await updatePositionInfo();
      syncZoomSlider();

      // 🔹 KEEP WRAP TYPE
      // const value = sessionStorage.getItem("selectedWrap");
      // if (value === "black") coverFrame("black");
      // if (value === "white") coverFrame("white");
      // if (value === "fit") fitImageToFrame(true);

      // 🔹 DPI UI
       const dpiElement = document.querySelector(".dpi-num");
      const iconElement = document.querySelector(".dpi-state-icon");
      const boostBtn = document.querySelector(".boost-img-btn");
      const currentDpi = Number((appState.dpi || 0).toFixed(2));

      if (dpiElement && iconElement && boostBtn) {
        
        iconElement.innerHTML = ""; // clear old icon

        if (currentDpi < 35) {
         dpiElement.textContent = `Needs Upscale`;
          dpiElement.style.color = "red";

          iconElement.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M9.9891 0C4.49317 0 0 4.49317 0 9.9891C0 15.4859 4.49317 20 9.9891 20C15.485 20 20 15.5068 20 9.9891C20 4.47115 15.5068 0 9.9891 0ZM9.9891 18.3208C5.40912 18.3208 1.67946 14.5911 1.67946 10.0111C1.67946 5.43115 5.40912 1.70148 9.9891 1.70148C14.5691 1.70148 18.2987 5.43115 18.2987 10.0111C18.3207 14.5911 14.5909 18.3208 9.9891 18.3208Z" fill="#FF0606"/>
<path d="M10.1207 4.56252C9.74952 4.56252 9.44421 4.69326 9.20466 4.93365C8.98621 5.1732 8.85547 5.52239 8.85547 5.93651C8.85547 6.24185 8.8774 6.72177 8.92126 7.41931L9.16081 10.9307C9.20466 11.4106 9.29154 11.7379 9.37926 11.9774C9.48806 12.2389 9.70651 12.3696 10.0118 12.3696C10.3172 12.3696 10.5137 12.2389 10.6444 11.9774C10.7532 11.7379 10.841 11.3887 10.8629 10.9526L11.1682 7.33156C11.2121 7.0043 11.2121 6.65511 11.2121 6.34977C11.2121 5.78297 11.1463 5.34691 10.9936 5.04073C10.884 4.7371 10.5787 4.56252 10.1207 4.56252Z" fill="#FF0606"/>
<path d="M10.0549 13.4844C9.72761 13.4844 9.44421 13.5932 9.20466 13.8336C8.96511 14.0731 8.85547 14.3354 8.85547 14.6627C8.85547 15.0338 8.9862 15.3391 9.2266 15.5348C9.46615 15.7313 9.75039 15.8402 10.0768 15.8402C10.3821 15.8402 10.6655 15.7313 10.9059 15.5129C11.1455 15.2944 11.277 14.6408 11.277 14.6408C11.277 14.3135 11.1682 14.0301 10.9278 13.7906C10.6655 13.5932 10.3813 13.4844 10.0549 13.4844Z" fill="#FF0606"/>
</svg>`;

          boostBtn.style.display = "flex";
          boostBtn.classList.add("show")

        } else {
         dpiElement.textContent = `Good To Print`;
          dpiElement.style.color = "green";

          iconElement.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M10 0C4.48421 0 0 4.48421 0 10C0 15.5158 4.48421 20 10 20C15.5158 20 20 15.5158 20 10C20 4.48421 15.5158 0 10 0ZM10 17.8105C5.68421 17.8105 2.18947 14.2947 2.18947 10C2.18947 5.70526 5.68421 2.18947 10 2.18947C14.3158 2.18947 17.8105 5.68421 17.8105 10C17.8105 14.3158 14.3158 17.8105 10 17.8105Z" fill="#1B8600"/>
<path d="M12.7139 6.92258L8.90337 10.7542L7.28232 9.13311C6.86127 8.71205 6.16653 8.71205 5.74548 9.13311C5.32442 9.55416 5.32442 10.2489 5.74548 10.6699L8.14548 13.0699C8.356 13.2805 8.62969 13.3857 8.92443 13.3857C9.21916 13.3857 9.49285 13.2805 9.70337 13.0699L14.2928 8.48047C14.7139 8.05942 14.7139 7.36469 14.2928 6.94363C13.8507 6.50153 13.156 6.50153 12.7139 6.92258Z" fill="#1B8600"/>
</svg>`;

          boostBtn.classList.remove("show");
          if (!boostBtn.classList.contains("show")) boostBtn.style.display = "none";
        
        }
      }
    });

     if (
  result?.message ===
  "We can not upscale this image further. Please try a different image."
) {
  console.log(result.message);
  if (savepopup) savepopup.style.display = "flex";
const savepopuptitle = document.querySelector(".save-image-title");
const savepopupicon = document.querySelector(".save-image-icon");
const savepopuptext = document.querySelector(".save-image-text");
const boostBtns = document.querySelectorAll(".boost-img-btn");

boostBtns.forEach(btn => {
  btn.classList.add("limit-reached");
});
if (savepopupicon) savepopupicon.style.display = "none";

if (result?.message === "We can not upscale this image further. Please try a different image.") {
  savepopuptitle.textContent = "Change Image";
  savepopuptext.textContent =
    "The image has reached its maximum resolution and cannot be upscaled further.";
}

   setTimeout(() => {
  if (savepopup) savepopup.style.display = "none";
}, 3000);
} else {
 // Show aftersave popup and hide savepopup after delay
    if (savepopup) savepopup.style.display = "none";
    
    if (afterSavePopup) {
      afterSavePopup.style.display = "flex";
      
      // Hide aftersave popup after 3-4 seconds
      setTimeout(() => {
        afterSavePopup.style.display = "none";
      }, 3500); // 3.5 seconds
    }
}
  

  } catch (err) {
    console.error("Upscale API failed:", err);
     if (savepopup) savepopup.style.display = "flex";

const savepopuptitle = document.querySelector(".save-image-title");
const savepopupicon = document.querySelector(".save-image-icon");
const savepopuptext = document.querySelector(".save-image-text");

if (savepopupicon) savepopupicon.style.display = "none";

if (err.message === "We can not upscale this image further. Please try a different image.") {
  savepopuptitle.textContent = "Change Image";
  savepopuptext.textContent =
    "The image has reached its maximum resolution and cannot be upscaled further.";
} else {
  savepopuptitle.textContent = "Upscale Failed";
  savepopuptext.textContent =
    "There was an issue while upscaling the image. Please try again.";
}

// Hide popup after 3 seconds
setTimeout(() => {
  if (savepopup) savepopup.style.display = "none";
}, 3000);
  }
}

function base64ToFile(base64, filename = "image.jpeg") {
  const arr = base64.split(",");
  const mime = arr[0].match(/:(.*?);/)[1];
  const bstr = atob(arr[1]);
  let n = bstr.length;
  const u8arr = new Uint8Array(n);
  while (n--) {
    u8arr[n] = bstr.charCodeAt(n);
  }
  return new File([u8arr], filename, { type: mime });
}

// Boost Button event
document.querySelector(".boost-img-btn").addEventListener("click", (e) => {

  // ✅ Continue normal flow
  const userId = window.shopifyCustomerId || "guest";
  const sessionId = getLocalStorage1Day("sessionId") || "none";

  const mainImgWrap = document.querySelector(".main-img-wrap");
  if (!mainImgWrap) {
    console.error("No .main-img-wrap found.");
    return;
  }

  const dpidata = appState.dpi || 0;
  const printHeightdata = appState.printimghight || 0;
  const printWidthdata = appState.printimgwidth || 0;

  const dataMainImg = mainImgWrap.getAttribute("data-main-img");
  if (!dataMainImg) {
    console.error("No data-main-img found.");
    return;
  }

  if (dataMainImg.startsWith("http")) {
    upscaleAndFixDPI({
      customerId: userId,
      sessionId: sessionId,
      dpi: dpidata,
      printWidth: printWidthdata,
      printHeight: printHeightdata,
      imageUrl: dataMainImg
    });
  } 
  else if (dataMainImg.startsWith("data:image")) {
    const file = base64ToFile(dataMainImg, "uploaded.jpeg");
    upscaleAndFixDPI({
      customerId: userId,
      sessionId: sessionId,
      dpi: dpidata,
      printWidth: printWidthdata,
      printHeight: printHeightdata,
      file: file
    });
  } 
  else {
    console.error("Invalid data-main-img format.");
  }
});

function getCroppedCanvas() {
  let innerPadding;

    const frnheight = appState.orgHeight;
  const frmwidth = appState.orgWidth;
  let size = `${frmwidth}x${frnheight}`;
  
if (window.innerWidth < 680) {
      if (size === "900x900") {
        innerPadding = 150 / 4.5;
      } else if (size === "1100x1100") {
        innerPadding = 150 / 5.5;
      } else if (size === "1100x1300") {
        innerPadding = 150 / 6.5;
      } else if (size === "1100x1500") {
        innerPadding = 150 / 7.5;
      } else if (size === "1200x1500") {
        innerPadding = 150 / 7.5;
      } else if (size === "1300x1300") {
        innerPadding = 150 / 6.5;
      } else if (size === "1300x2300") {
        innerPadding = 150 / 11.5;
      } else if (size === "100x1700") {
        innerPadding = 150 / 8.5;
      } else if (size === "1800x1800") {
        innerPadding = 300 / 9;
      } else if (size === "1800x2200") {
        innerPadding = 300 / 11;
      } else if (size === "1500x2100") {
        innerPadding = 150 / 10.5;
      } else if (size === "1500x2700") {
        innerPadding = 150 / 13.5;
      } else if (size === "1500x3900") {
        innerPadding = 150 / 19.5;
      } else if (size === "1700x1700") {
        innerPadding = 150 / 8.5;
      } else if (size === "2200x2200") {
        innerPadding = 300 / 11;
      } else if (size === "2200x2600") {
        innerPadding = 300 / 13;
      } else if (size === "1900x2700") {
        innerPadding = 150 / 13.5;
      } else if (size === "1900x3500") {
        innerPadding = 150 / 17.5;
      } else if (size === "1900x5100") {
        innerPadding = 150 / 25.5;
      } else if (size === "2100x2100") {
        innerPadding = 150 / 10.5;
      } else if (size === "2400x3000") {
        innerPadding = 300 / 15;
      } else if (size === "2100x2900") {
        innerPadding = 150 / 14.5;
      } else if (size === "2300x2300") {
        innerPadding = 150 / 11.5;
      } else if (size === "2300x2700") {
        innerPadding = 150 / 13.5;
      } else if (size === "2300x3100") {
        innerPadding = 150 / 15.5;
      } else if (size === "2300x3300") {
        innerPadding = 150 / 16.5;
      } else if (size === "2300x4300") {
        innerPadding = 150 / 21.5;
      } else if (size === "2300x6300") {
        innerPadding = 150 / 31.5;
      } else if (size === "2700x2700") {
        innerPadding = 150 / 13.5;
      } else if (size === "2700x3300") {
        innerPadding = 150 / 16.5;
      } else if (size === "2700x3500") {
        innerPadding = 150 / 17.5;
      } else if (size === "3000x4200") {
        innerPadding = 300 / 21;
      } else if (size === "2700x5100") {
        innerPadding = 150 / 25.5;
      } else if (size === "2900x2900") {
        innerPadding = 150 / 14.5;
      } else if (size === "2900x4300") {
        innerPadding = 150 / 21.5;
      } else if (size === "3100x3100") {
        innerPadding = 150 / 15.5;
      } else if (size === "3100x4300") {
        innerPadding = 150 / 21.5;
      } else if (size === "3300x3300") {
        innerPadding = 150 / 16.5;
      } else if (size === "3300x4300") {
        innerPadding = 150 / 21.5;
      } else if (size === "3300x6300") {
        innerPadding = 150 / 31.5;
      } else if (size === "3500x3500") {
        innerPadding = 150 / 17.5;
      } else if (size === "3500x5100") {
        innerPadding = 150 / 25.5;
      } else if (size === "3900x3900") {
        innerPadding = 150 / 19.5;
      } else if (size === "4000x4000") {
        innerPadding = 150 / 20;
      } else if (size === "4300x5800") {
        innerPadding = 150 / 29;
      } else if (size === "4300x6300") {
        innerPadding = 150 / 31.5;
      } else {
        innerPadding = null;
      }
} else {

 if (size === "900x900") {
        innerPadding = 150 / 2.25;
      } else if (size === "1100x1100") {
        innerPadding = 150 / 2.75;
      } else if (size === "1100x1300") {
        innerPadding = 150 / 3.25;
      } else if (size === "1100x1500") {
        innerPadding = 150 / 3.75;
      } else if (size === "1200x1500") {
        innerPadding = 150 / 3.75;
      } else if (size === "1300x1300") {
        innerPadding = 150 / 3.25;
      } else if (size === "1300x2300") {
        innerPadding = 150 / 5.75;
      } else if (size === "1400x1700") {
        innerPadding = 150 / 4.25;
      } else if (size === "1800x1800") {
        innerPadding = 300 / 4.5;
      } else if (size === "1800x2200") {
        innerPadding = 300 / 5.5;
      } else if (size === "1500x2100") {
        innerPadding = 150 / 5.25;
      } else if (size === "1500x2700") {
        innerPadding = 150 / 6.75;
      } else if (size === "1500x3900") {
        innerPadding = 150 / 9.75;
      } else if (size === "1700x1700") {
        innerPadding = 150 / 4.25;
      } else if (size === "2200x2200") {
        innerPadding = 300 / 5.5;
      } else if (size === "2200x2600") {
        innerPadding = 300 / 6.5;
      } else if (size === "1900x2700") {
        innerPadding = 150 / 6.75;
      } else if (size === "1900x3500") {
        innerPadding = 150 / 8.75;
      } else if (size === "1900x5100") {
        innerPadding = 150 / 12.75;
      } else if (size === "2100x2100") {
        innerPadding = 150 / 5.25;
      } else if (size === "2400x3000") {
        innerPadding = 300 / 7.5;
      } else if (size === "2100x2900") {
        innerPadding = 150 / 7.25;
      } else if (size === "2300x2300") {
        innerPadding = 150 / 5.75;
      } else if (size === "2300x2700") {
        innerPadding = 150 / 6.75;
      } else if (size === "2300x3100") {
        innerPadding = 150 / 7.75;
      } else if (size === "2300x3300") {
        innerPadding = 150 / 8.25;
      } else if (size === "2300x4300") {
        innerPadding = 150 / 10.75;
      } else if (size === "2300x6300") {
        innerPadding = 150 / 15.75;
      } else if (size === "2700x2700") {
        innerPadding = 150 / 6.75;
      } else if (size === "2700x3300") {
        innerPadding = 150 / 8.25;
      } else if (size === "2700x3500") {
        innerPadding = 150 / 8.75;
      } else if (size === "3000x4200") {
        innerPadding = 300 / 10.5;
      } else if (size === "2700x5100") {
        innerPadding = 150 / 12.75;
      } else if (size === "2900x2900") {
        innerPadding = 150 / 7.25;
      } else if (size === "2900x4300") {
        innerPadding = 150 / 10.75;
      } else if (size === "3100x3100") {
        innerPadding = 150 / 7.75;
      } else if (size === "3100x4300") {
        innerPadding = 150 / 10.75;
      } else if (size === "3300x3300") {
        innerPadding = 150 / 8.25;
      } else if (size === "3300x4300") {
        innerPadding = 150 / 10.75;
      } else if (size === "3300x6300") {
        innerPadding = 150 / 15.75;
      } else if (size === "3500x3500") {
        innerPadding = 150 / 8.75;
      } else if (size === "3500x5100") {
        innerPadding = 150 / 12.75;
      } else if (size === "3900x3900") {
        innerPadding = 150 / 9.75;
      } else if (size === "4000x4000") {
        innerPadding = 150 / 10;
      } else if (size === "4300x5800") {
        innerPadding = 150 / 14.5;
      } else if (size === "4300x6300") {
        innerPadding = 150 / 15.75;
      } else {
        innerPadding = null;
      }
}

  const sw = canvas.width - innerPadding * 2;
  const sh = canvas.height - innerPadding * 2;

  mockupState.croppedWidth = sw;
  mockupState.croppedHeight = sh;

  const cropped = document.createElement("canvas");
  cropped.width = sw;
  cropped.height = sh;
  const ctx = cropped.getContext("2d");

  ctx.drawImage(
    canvas.lowerCanvasEl,
    innerPadding, innerPadding, sw, sh,
    0, 0, sw, sh
  );

  return cropped;
}

// Function to insert cropped image into mockups
function insertIntoMockups() {
  const croppedCanvas = getCroppedCanvas();
  const mockupCanvases = document.querySelectorAll(".mockup-canvas");

  mockupCanvases.forEach((mockupCanvas, index) => {
    const ctx = mockupCanvas.getContext("2d");
    ctx.clearRect(0, 0, mockupCanvas.width, mockupCanvas.height);

    const { x, y, w, h } = mockupPlacements[index];

    ctx.drawImage(
      croppedCanvas,
      mockupCanvas.width * x,
      mockupCanvas.height * y,
      mockupCanvas.width * w,
      mockupCanvas.height * h
    );
  });
}

document.getElementById("insertBtn")?.addEventListener("click", insertIntoMockups);

document.addEventListener("DOMContentLoaded", () => {
    const currentUrl = window.location.pathname; 
    const links = document.querySelectorAll(".pdp-tab-wrap .pill");

    links.forEach(link => {
      if (link.getAttribute("href") === currentUrl) {
        link.classList.add("active");
      }
    });
});

document.addEventListener("DOMContentLoaded", function () {
  const highlightedOptions = [];

  const relatedOptionsMap = {
    '9″×12″': ["18″×26″", "20″×28″", "28″×40″", "40″×55″"],
    '12″×16″': ["18″×26″", "20″×28″", "28″×40″", "40″×55″"],
    '18″×24″': ["18″×26″", "20″×28″", "28″×40″", "40″×55″"],
    '24″×32″': ["18″×26″", "20″×28″", "28″×40″", "40″×55″"],
    '30″×40″': ["18″×26″", "20″×28″", "28″×40″", "40″×55″"],
    '8″×12″': ["26″×40″"],
    '12″×18″': ["26″×40″"],
    '16″×24″': ["26″×40″"],
    '20″×30″': ["26″×40″"],
    '24″×36″': ["26″×40″"],
    '32″×48″': ["26″×40″"],
    '40″×60″': ["26″×40″"],
    '8″×10″': ["11″×14″", "20″×24″"],
    '16″×20″': ["11″×14″", "20″×24″"],
    '24″×30″': ["11″×14″", "20″×24″"],
  };

  function highlightMatchingOption() {
  const hiddenimg = document.getElementById("frame-img-position");
  const orientationRadio = document.querySelector('input[name="orientation"]:checked');
  const orientation = orientationRadio ? orientationRadio.value : "portrait";

  // ⛔ STOP if orientation is NOT portrait
  if (orientation !== "portrait") {
    return true;  // stop interval
  }

  const imgRatioEl = document.getElementById("img-ratio");
  if (!imgRatioEl) {
    return;
  }

  const ratioValue = imgRatioEl.textContent.trim() || imgRatioEl.value?.trim();
  if (!ratioValue) {
    return false;
  }

  const options = document.querySelectorAll("#frameSizeOptions label.frame-size-btn input");
  let matchFound = false;

  options.forEach((input, index) => {
    const lRatio = input.getAttribute("data-l-ratio");
    const pRatio = input.getAttribute("data-p-ratio");
    const label = input.closest("label.frame-size-btn").querySelector("span");

      if (ratioValue === lRatio || ratioValue === pRatio) {
        label.style.border = "1px solid green";
        
        matchFound = true;

        if (!highlightedOptions.includes(input.value)) {
          highlightedOptions.push(input.value);
        }
      } 
    });

    if (matchFound) {
      highlightedOptions.forEach((val) => {
        if (relatedOptionsMap[val]) {
          relatedOptionsMap[val].forEach((relatedVal) => {
            highlightRelatedOption(relatedVal);
          });
        }
      });
    }

    return true;
  }

function highlightRelatedOption(targetValue) {
  const options = document.querySelectorAll("#frameSizeOptions label.frame-size-btn input ");
  let found = false;

  options.forEach((input) => {
    const normalizedInput = input.value.replace(/[“”"]/g, '"').replace(/[×x]/g, "x");
    const normalizedTarget = targetValue.replace(/[“”"]/g, '"').replace(/[×x]/g, "x");
    if (normalizedInput === normalizedTarget) {
      const label = input.closest("label.frame-size-btn").querySelector("span");
      label.style.border = "1px solid orange";
       
      found = true;

      if (!highlightedOptions.includes(input.value)) {
        highlightedOptions.push(input.value);
      }
    }
  });
}

const ratioCheckInterval = setInterval(() => {
  const done = highlightMatchingOption();
  if (done) {
    clearInterval(ratioCheckInterval);
  }
}, 300);
});

const canvasnew = document.getElementById('canvasnew');
const fileInput1 = document.getElementById('upload-image');
const ctx = canvasnew.getContext('2d');
const expandBtn = document.getElementById('expandBtn');

let img = new Image();
img.crossOrigin = "anonymous";

// 🧮 Calculate expanded size
function calculateExpandedSize({
  imageWidthPx,
  imageHeightPx,
  imageWidthInch,
  imageHeightInch,
  canvasWidthInch,
  canvasHeightInch
}) {
  const extraWidthInch = canvasWidthInch - imageWidthInch;
  const extraHeightInch = canvasHeightInch - imageHeightInch;

  const extraWidthPx = (extraWidthInch * imageWidthPx) / imageWidthInch;
  const extraHeightPx = (extraHeightInch * imageHeightPx) / imageHeightInch;

  const finalWidthPx = imageWidthPx + extraWidthPx;
  const finalHeightPx = imageHeightPx + extraHeightPx;

  return { extraWidthPx, extraHeightPx, finalWidthPx, finalHeightPx };
}

expandBtn.addEventListener('click', async () => {
  if (!appState.uploadedImage) {
    alert("Please upload an image first!");
    return;
  }

  const imgWidthPx = appState.uploadedImage.width;
  const imgHeightPx = appState.uploadedImage.height;
  const imgWidthIn = appState.printimgwidth;
  const imgHeightIn = appState.printimghight;
  const canvasWidthIn = appState.extendwidth;
  const canvasHeightIn = appState.extendheight;

  // ✅ Get user and session IDs
  const userId = window.shopifyCustomerId || "guest";
  const sessionId = getLocalStorage1Day("sessionId") || "none";

  if (!fileInput1.files[0]) {
    alert("Please upload an image first!");
    return;
  }

  const size = calculateExpandedSize({
    imageWidthPx: imgWidthPx,
    imageHeightPx: imgHeightPx,
    imageWidthInch: imgWidthIn,
    imageHeightInch: imgHeightIn,
    canvasWidthInch: canvasWidthIn,
    canvasHeightInch: canvasHeightIn
  });

  const reader = new FileReader();
  reader.onload = e => {
    img.src = e.target.result;
    img.onload = async () => await processImage(size);
  };
  reader.readAsDataURL(fileInput1.files[0]);

  // 🧩 Process & Upload
  async function processImage(size) {
    const { finalWidthPx, finalHeightPx } = size;

    // Draw expanded image
    canvasnew.width = finalWidthPx;
    canvasnew.height = finalHeightPx;

    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, canvasnew.width, canvasnew.height);

    const x = (canvasnew.width - imgWidthPx) / 2;
    const y = (canvasnew.height - imgHeightPx) / 2;

    ctx.drawImage(img, x, y, imgWidthPx, imgHeightPx);

    // Convert to Blob
    const blob = await new Promise(resolve => canvasnew.toBlob(resolve, 'image/jpeg'));
    const file = new File([blob], "expanded-image.jpeg", { type: "image/jpeg" });

    // 🔹 Prepare FormData
    const formData = new FormData();
    formData.append("customerId", userId);
    formData.append("sessionId", sessionId);
    formData.append("file", file);

    try {
      const response = await fetch(`${window.Prompt2Prints.apiBase}/upload-image`, {
        method: "POST",
              headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
        body: formData
      });

      if (!response.ok) throw new Error(`Upload failed (${response.status})`);
      const result = await response.json();

      const imageUpscale = document.querySelector('input[name="properties[_pdp-allow-upscale]"]');
const imageUpscaletag = document.querySelector('input[name="properties[_pdp-img-tag]"]');

if (!imageUpscale || !imageUpscaletag) {
  console.warn("Upscale inputs not found");
  return;
}

const flag = (result.flag || "").toLowerCase();

if (flag === "standard") {
  imageUpscale.value = "true";
  imageUpscaletag.value = "Standard";
} 
else if (flag === "professional") {
  imageUpscale.value = "false";
  imageUpscaletag.value = "Professional";
} 
else {
  imageUpscale.value = "";
  imageUpscaletag.value = "";
}

// Optional: also update attribute for Shopify forms
imageUpscale.setAttribute("value", imageUpscale.value);
imageUpscaletag.setAttribute("value", imageUpscaletag.value);
      // 🖼️ Auto-download after successful upload
      const base64 = canvasnew.toDataURL('image/jpeg');
      const link = document.createElement('a');
      link.download = 'expanded-image.jpeg';
      link.href = base64;
      link.click();

    } catch (err) {
      console.error("❌ Upload error:", err);
      alert("Upload failed. Please try again.");
    }
  }
});

// CORRECTED BLACK EDGE CANVAS CODE
const canvasnewblack = document.getElementById('canvasblackedge');
const ctx1 = canvasnewblack.getContext('2d');

let img1 = new Image();
img1.crossOrigin = "anonymous";

uploadInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (event) => {
    img1.src = event.target.result;

    img1.onload = () => {
      appState.uploadedImageForBlackEdge = img1.src;
    };
  };

  reader.readAsDataURL(file);
});
async function generateCanvasWithBlackEdge() {

  // Enhanced image loading function that handles all source types
  const loadImageFromSource = async (source) => {
    return new Promise((resolve, reject) => {

      // Case 1: Already an HTMLImageElement
      if (source instanceof HTMLImageElement) {
        if (source.complete && source.naturalHeight !== 0) {
          resolve(source);
        } else {
          source.onload = () => {
            resolve(source);
          };
          source.onerror = (e) => {
            console.error("HTMLImageElement load error:", e);
            reject(new Error('Failed to load image element'));
          };
        }
        return;
      }

      // Case 2: String (URL, base64, or blob URL)
      if (typeof source === 'string') {
        
        // Check if it's a data URL (base64)
        if (source.startsWith('data:')) {
          const img = new Image();
          img.onload = () => {
            resolve(img);
          };
          img.onerror = (e) => {
            console.error("Data URL image load error:", e);
            reject(new Error('Failed to load data URL image'));
          };
          img.src = source;
          return;
        }
        
        // Check if it's a blob URL
        if (source.startsWith('blob:')) {
          const img = new Image();
          img.onload = () => {
            resolve(img);
          };
          img.onerror = (e) => {
            console.error("Blob URL image load error:", e);
            reject(new Error('Failed to load blob URL image'));
          };
          img.src = source;
          return;
        }
        
        const img = new Image();
        
        // Important: Set crossOrigin for external URLs
        img.crossOrigin = "anonymous";
        
        img.onload = () => {
          resolve(img);
        };
        
        img.onerror = (e) => {
          console.error("External image load error:", e);
          console.error("Failed to load URL:", source);
          
          const fallbackImg = new Image();
          fallbackImg.onload = () => {
            resolve(fallbackImg);
          };
          fallbackImg.onerror = (fallbackError) => {
            console.error("Fallback also failed:", fallbackError);
            reject(new Error(`Failed to load image from URL: ${source}`));
          };
          fallbackImg.src = source;
        };
        
        img.src = source;
        return;
      }

      // Case 3: File or Blob object
      if (source instanceof File || source instanceof Blob) {
        const reader = new FileReader();
        reader.onload = function(e) {
          const img = new Image();
          img.onload = () => {
            resolve(img);
          };
          img.onerror = (e) => {
            console.error("File/Blob image load error:", e);
            reject(new Error('Failed to load file/blob image'));
          };
          img.src = e.target.result;
        };
        reader.onerror = (e) => {
          console.error("FileReader error:", e);
          reject(new Error('Failed to read file'));
        };
        reader.readAsDataURL(source);
        return;
      }

      // Case 4: Canvas element
      if (source instanceof HTMLCanvasElement) {
        const img = new Image();
        img.onload = () => {
          resolve(img);
        };
        img.onerror = (e) => {
          console.error("Canvas image load error:", e);
          reject(new Error('Failed to load canvas image'));
        };
        img.src = source.toDataURL();
        return;
      }

      // Case 5: If it's an object with src, url, or imageUrl property
      if (source && typeof source === 'object') {
        
        // Check for common image source properties
        let imageUrl = null;
        
        if (source.src) {
          imageUrl = source.src;
        } else if (source.url) {
          imageUrl = source.url;
        } else if (source.imageUrl) {
          imageUrl = source.imageUrl;
        } else if (source.data) {
          imageUrl = source.data;
        } else if (source.image) {
          imageUrl = source.image;
        } else if (source.link) {
          imageUrl = source.link;
        }
        
        if (imageUrl) {
          loadImageFromSource(imageUrl).then(resolve).catch(reject);
          return;
        }
        
        // Check if it's an object that can be converted to data URL
        if (source.toDataURL) {
          try {
            const dataUrl = source.toDataURL();
            loadImageFromSource(dataUrl).then(resolve).catch(reject);
            return;
          } catch (e) {
            console.error("Error converting object to data URL:", e);
          }
        }
      }

      // Case 6: If it's an object that might contain the actual image data
      // Try to stringify and see if it contains a URL
      if (source && typeof source === 'object') {
        const stringified = JSON.stringify(source);
        
        // Look for URL patterns in the stringified object
        const urlRegex = /(https?:\/\/[^\s"]+\.(png|jpg|jpeg|gif|webp))/i;
        const match = stringified.match(urlRegex);
        
        if (match) {
          const foundUrl = match[0];
          loadImageFromSource(foundUrl).then(resolve).catch(reject);
          return;
        }
      }

      try {
        const img = new Image();
        img.onload = () => {
          resolve(img);
        };
        img.onerror = (e) => {
          console.error("Unknown source type load failed:", e);
          reject(new Error(`Unsupported image source type: ${typeof source}`));
        };
        
        // Try to set src directly (might work for some object types)
        if (source instanceof Object) {
          // If it has a toString method, use it
          img.src = source.toString();
        } else {
          img.src = source;
        }
      } catch (finalError) {
        console.error("Final attempt failed:", finalError);
        reject(new Error(`Unsupported image source type: ${typeof source}. Object details: ${JSON.stringify(source)}`));
      }
    });
  };

 
  updatePositionInfo();

  // Use the main uploaded image or the black edge specific image
  const imageSource = appState.uploadedImageForBlackEdge || appState.uploadedImage;

  if (!imageSource) {
    alert("Please upload an image first!");
    throw new Error("No image source found");
  }

  if (!appState.newCanvasWidth || !appState.newCanvasHeight) {
    alert("Canvas dimensions not calculated. Please position the image first.");
    throw new Error("Canvas dimensions not calculated");
  }

  // Set canvas size
  canvasnewblack.width = appState.newCanvasWidth;
  canvasnewblack.height = appState.newCanvasHeight;

  // Fill background
  ctx1.fillStyle = appState.canvasBgColor || "#000";
  ctx1.fillRect(0, 0, canvasnewblack.width, canvasnewblack.height);

  // Helper function to convert base64 to blob
  const base64ToBlob = (base64Data) => {
    const parts = base64Data.split(';base64,');
    const contentType = parts[0].split(':')[1];
    const raw = window.atob(parts[1]);
    const uInt8Array = new Uint8Array(raw.length);
    
    for (let i = 0; i < raw.length; ++i) {
      uInt8Array[i] = raw.charCodeAt(i);
    }
    
    return new Blob([uInt8Array], { type: contentType });
  };

  // Helper function to get/set localStorage with 1-day expiry
  const getLocalStorage1Day = (key) => {
    try {
      const item = localStorage.getItem(key);
      if (!item) return null;
      
      // Check if it's already a JSON string with expiry
      if (item.startsWith('{') && item.includes('"expiry"')) {
        const { value, expiry } = JSON.parse(item);
        if (Date.now() > expiry) {
          localStorage.removeItem(key);
          return null;
        }
        return value;
      } else {
        // It's a regular string, return as-is
        return item;
      }
    } catch (error) {
      console.error('Error reading from localStorage:', error);
      // Return the raw item if parsing fails
      return localStorage.getItem(key);
    }
  };

  // Function to upload to image-thumbnail API (similar to exportFullDivAsImage)
  const uploadToThumbnailAPI = async (cloudfrontLink, customerId, sessionId) => {
    try {
    
      
      // let blob;
      // if (imageData.startsWith("data:")) {
      //   const res = await fetch(imageData);
      //   blob = await res.blob();
      // } else {
      //   // If it's already a blob or file
      //   blob = imageData;
      // }

      const formData = new FormData();
      // formData.append("file", blob, "full-div-image.jpeg");
      formData.append("customerId", customerId);
      formData.append("sessionId", sessionId);
      formData.append("thumbnailWidth", "200");
      formData.append("imageUrl", cloudfrontLink);
      const response = await fetch(`${window.Prompt2Prints.apiBase}/image-thumbnail`, {
        method: "POST",
              headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Thumbnail API responded with status: ${response.status}`);
      }

      const data = await response.json();

      // Store thumbnail URLs
      const hiddenInput = document.getElementById("preview-image-data");
      if (hiddenInput && data.original?.cloudfrontUrl) {
        hiddenInput.value = data.original.cloudfrontUrl;
      }

      const hiddenInput1 = document.getElementById("preview-thumb-image-data");
      if (hiddenInput1 && data.thumbnail?.cloudfrontUrl) {
        hiddenInput1.value = data.thumbnail.cloudfrontUrl;
      }

      return data;
    } catch (error) {
      console.error("❌ Thumbnail API upload failed:", error);
      throw error;
    }
  };

  try {


    const image = await loadImageFromSource(imageSource);

    // Get dimensions from UI or use image natural dimensions as fallback
    const filewvalue = parseFloat(document.getElementById("img-file-w")?.textContent) || image.naturalWidth || 0;
    const filehvalue = parseFloat(document.getElementById("img-file-h")?.textContent) || image.naturalHeight || 0;
    
    appState.imageWidth = filewvalue;
    appState.imageheight = filehvalue;
    
    
    // Clear and redraw background (in case image loading took time)
    ctx1.fillStyle = appState.canvasBgColor || "#000";
    ctx1.fillRect(0, 0, canvasnewblack.width, canvasnewblack.height);
    
    // Draw the image
    ctx1.drawImage(
      image,
      appState.newimageleft || 0,
      appState.newimagetop || 0,
      filewvalue,
      filehvalue
    );

    // Draw border
    ctx1.strokeStyle = appState.borderColor || "#000000";
    ctx1.lineWidth = (appState.newBorder || 10) * 2;

    ctx1.strokeRect(
      appState.newBorder || 5,
      appState.newBorder || 5,
      canvasnewblack.width - (appState.newBorder || 10) * 2,
      canvasnewblack.height - (appState.newBorder || 10) * 2
    );

    const uploadResult = await new Promise(async (resolve, reject) => {
      try {
        canvasnewblack.toBlob(async function(blob) {
          if (!blob) {
            reject(new Error('Failed to create blob from canvas'));
            return;
          }
          
          const file = new File([blob], "canvas-with-black-edge.jpeg", { type: "image/jpeg" });
          // Download locally
          const link = document.createElement('a');
          link.download = file.name;
          link.href = URL.createObjectURL(file);
          link.click();
          URL.revokeObjectURL(link.href);
          
          // Upload to both APIs
          try {
            const formData = new FormData();
            const userId = window.shopifyCustomerId || "guest";
            const sessionId = getLocalStorage1Day("sessionId") || "none";

            // Convert canvas to data URL for API upload
            const imageData = canvasnewblack.toDataURL("image/jpeg");
            
            if (imageData.startsWith("http") || imageData.startsWith("//")) {
              formData.append("imageUrl", imageData);
            } else if (imageData.startsWith("data:image/")) {
              const imageBlob = base64ToBlob(imageData);
              formData.append("file", imageBlob, "uploaded-image.jpeg");
            } else {
              reject(new Error("Invalid image data format"));
              return;
            }

            formData.append("customerId", userId);
            formData.append("sessionId", sessionId);
            const response = await fetch(`${window.Prompt2Prints.apiBase}/upload-image`, {
              method: "POST",
              headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
              body: formData,
            });
            
            if (!response.ok) {
              throw new Error(`Main API responded with status: ${response.status}`);
            }
            
            const data = await response.json();
  const imageUpscale = document.querySelector('input[name="properties[_pdp-allow-upscale]"]');
const imageUpscaletag = document.querySelector('input[name="properties[_pdp-img-tag]"]');

if (!imageUpscale || !imageUpscaletag) {
  console.warn("Upscale inputs not found");
  return;
}

const flag = (data.flag || "").toLowerCase();

if (flag === "standard") {
  imageUpscale.value = "true";
  imageUpscaletag.value = "Standard";
} 
else if (flag === "professional") {
  imageUpscale.value = "false";
  imageUpscaletag.value = "Professional";
} 
else {
  imageUpscale.value = "";
  imageUpscaletag.value = "";
}

// Optional: also update attribute for Shopify forms
imageUpscale.setAttribute("value", imageUpscale.value);
imageUpscaletag.setAttribute("value", imageUpscaletag.value);

            let cloudfrontLink = null;
            let thumbnailData = null;

            // Store the CloudFront link from main API
            if (data.cloudfrontLink) {
              cloudfrontLink = data.cloudfrontLink;
              
              const hiddenInput = document.getElementById("final-image-data");
              if (hiddenInput) {
                hiddenInput.value = cloudfrontLink;
              } else {
                console.warn("❌ Hidden input with id 'final-image-data' not found");
              }
              
              const cvswElement = parseFloat(document.getElementById("cvs-w")?.textContent) || 0;
              const cvshElement = parseFloat(document.getElementById("cvs-h")?.textContent) || 0;
              const hiddenimg = document.getElementById("frame-img-position");
                 const orientationRadio = document.querySelector('input[name="orientation"]:checked');
    const orientation = orientationRadio ? orientationRadio.value : "portrait";
    if(orientation == "portrait"){
        if (hiddenimg) {
                hiddenimg.value = JSON.stringify({
                  area_width: cvswElement,
                  area_height: cvshElement,
                  width: cvswElement,
                  height: cvshElement,
                  top: 0,
                  left: 0,
                });
              }
    }
    else if(orientation == "landscape"){
      if (hiddenimg) {
                hiddenimg.value = JSON.stringify({
                  area_width: cvshElement,
                  area_height: cvswElement,
                  width: cvshElement,
                  height: cvswElement,
                  top: 0,
                  left: 0,
                });
              }
    }
              
              // Also store in appState for easy access
              appState.generatedImageUrl = cloudfrontLink;
            } else {
              console.warn("❌ No cloudfrontLink in main API response");
            }

            try {
              thumbnailData = await uploadToThumbnailAPI(cloudfrontLink, userId, sessionId);
            } catch (thumbnailError) {
              console.error("❌ Thumbnail API upload failed, but continuing:", thumbnailError);
              // Don't reject here, as main upload was successful
            }

            resolve({ 
              success: true, 
              cloudfrontLink: cloudfrontLink,
              thumbnailData: thumbnailData,
              mainApiData: data
            });
            
          } catch (apiError) {
            console.error("❌ API upload failed:", apiError);
            reject(apiError);
          }
        }, 'image/jpeg');
      } catch (blobError) {
        console.error("Error creating blob:", blobError);
        reject(blobError);
      }
    });

    return uploadResult;

  } catch (error) {
    console.error('Error in generateCanvasWithBlackEdge:', error);
    throw error; // Re-throw to be caught by the parent function
  }
}

// Make the function globally accessible
window.generateCanvasWithBlackEdge = generateCanvasWithBlackEdge;

async function uploadRenderedEdgeCanvas(renderCanvas, fileName) {
  const base64ToBlob = (base64Data) => {
    const parts = base64Data.split(';base64,');
    const contentType = parts[0].split(':')[1];
    const raw = window.atob(parts[1]);
    const uInt8Array = new Uint8Array(raw.length);

    for (let i = 0; i < raw.length; ++i) {
      uInt8Array[i] = raw.charCodeAt(i);
    }

    return new Blob([uInt8Array], { type: contentType });
  };

  const uploadToThumbnailAPI = async (cloudfrontLink, customerId, sessionId) => {
    const formData = new FormData();
    formData.append("customerId", customerId);
    formData.append("sessionId", sessionId);
    formData.append("thumbnailWidth", "200");
    formData.append("imageUrl", cloudfrontLink);

    const response = await fetch(`${window.Prompt2Prints.apiBase}/image-thumbnail`, {
      method: "POST",
      headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
      body: formData,
    });

    if (!response.ok) {
      throw new Error(`Thumbnail API responded with status: ${response.status}`);
    }

    const data = await response.json();

    const previewInput = document.getElementById("preview-image-data");
    if (previewInput && data.original?.cloudfrontUrl) {
      previewInput.value = data.original.cloudfrontUrl;
    }

    const previewThumbInput = document.getElementById("preview-thumb-image-data");
    if (previewThumbInput && data.thumbnail?.cloudfrontUrl) {
      previewThumbInput.value = data.thumbnail.cloudfrontUrl;
    }

    return data;
  };

  return new Promise((resolve, reject) => {
    renderCanvas.toBlob(async (blob) => {
      if (!blob) {
        reject(new Error("Failed to create blob from canvas"));
        return;
      }

      try {
        const formData = new FormData();
        const userId = window.shopifyCustomerId || "guest";
        const sessionId = getLocalStorage1Day("sessionId") || "none";
        const imageData = renderCanvas.toDataURL("image/jpeg");

        if (imageData.startsWith("http") || imageData.startsWith("//")) {
          formData.append("imageUrl", imageData);
        } else if (imageData.startsWith("data:image/")) {
          const imageBlob = base64ToBlob(imageData);
          formData.append("file", imageBlob, fileName);
        } else {
          reject(new Error("Invalid image data format"));
          return;
        }

        formData.append("customerId", userId);
        formData.append("sessionId", sessionId);

        const response = await fetch(`${window.Prompt2Prints.apiBase}/upload-image`, {
          method: "POST",
          headers: {
            "x-api-key": window.Prompt2Prints.apiKey
          },
          body: formData,
        });

        if (!response.ok) {
          throw new Error(`Main API responded with status: ${response.status}`);
        }

        const data = await response.json();
        const imageUpscale = document.querySelector('input[name="properties[_pdp-allow-upscale]"]');
        const imageUpscaletag = document.querySelector('input[name="properties[_pdp-img-tag]"]');

        if (imageUpscale && imageUpscaletag) {
          const flag = (data.flag || "").toLowerCase();

          if (flag === "standard") {
            imageUpscale.value = "true";
            imageUpscaletag.value = "Standard";
          } else if (flag === "professional") {
            imageUpscale.value = "false";
            imageUpscaletag.value = "Professional";
          } else {
            imageUpscale.value = "";
            imageUpscaletag.value = "";
          }

          imageUpscale.setAttribute("value", imageUpscale.value);
          imageUpscaletag.setAttribute("value", imageUpscaletag.value);
        }

        let thumbnailData = null;
        if (data.cloudfrontLink) {
          const hiddenInput = document.getElementById("final-image-data");
          if (hiddenInput) {
            hiddenInput.value = data.cloudfrontLink;
          }

          const cvswElement = parseFloat(document.getElementById("cvs-w")?.textContent) || 0;
          const cvshElement = parseFloat(document.getElementById("cvs-h")?.textContent) || 0;
          const hiddenimg = document.getElementById("frame-img-position");
          const orientationRadio = document.querySelector('input[name="orientation"]:checked');
          const orientation = orientationRadio ? orientationRadio.value : "portrait";

          if (hiddenimg) {
            const payload = orientation === "landscape"
              ? {
                  area_width: cvshElement,
                  area_height: cvswElement,
                  width: appState.newCanvasHeight,
                  height: appState.newCanvasWidth,
                  top: 0,
                  left: 0,
                }
              : {
                  area_width: cvswElement,
                  area_height: cvshElement,
                  width: appState.newCanvasWidth,
                  height: appState.newCanvasHeight,
                  top: 0,
                  left: 0,
                };

            hiddenimg.value = JSON.stringify(payload);
          }

          appState.generatedImageUrl = data.cloudfrontLink;
          thumbnailData = await uploadToThumbnailAPI(data.cloudfrontLink, userId, sessionId);
        }

        resolve({
          success: true,
          cloudfrontLink: data.cloudfrontLink,
          thumbnailData,
          mainApiData: data
        });
      } catch (error) {
        reject(error);
      }
    }, "image/jpeg");
  });
}

async function generateCanvasWithMirrorEdge() {
  updatePositionInfo();

  const imageSource = appState.uploadedImageForBlackEdge || appState.uploadedImage;

  if (!imageSource) {
    alert("Please upload an image first!");
    throw new Error("No uploaded image found");
  }

  if (!appState.newCanvasWidth || !appState.newCanvasHeight) {
    alert("Canvas dimensions not calculated. Please position the image first.");
    throw new Error("Canvas dimensions not calculated");
  }

  const edgeSize = Number(appState.newBorder || 0);
  if (!Number.isFinite(edgeSize) || edgeSize <= 0) {
    throw new Error("Mirror edge size is invalid");
  }

  const faceWidth = Math.max(1, Math.round(appState.newCanvasWidth - edgeSize * 2));
  const faceHeight = Math.max(1, Math.round(appState.newCanvasHeight - edgeSize * 2));
  const image = await loadImageFromAnySource(imageSource);
  const filewvalue = parseFloat(document.getElementById("img-file-w")?.textContent) || image.naturalWidth || image.width || 0;
  const filehvalue = parseFloat(document.getElementById("img-file-h")?.textContent) || image.naturalHeight || image.height || 0;

  const compositionCanvas = document.createElement("canvas");
  compositionCanvas.width = Math.max(1, Math.round(appState.newCanvasWidth));
  compositionCanvas.height = Math.max(1, Math.round(appState.newCanvasHeight));

  const compositionCtx = compositionCanvas.getContext("2d");
  if (!compositionCtx) {
    throw new Error("Unable to create mirror composition canvas");
  }

  compositionCtx.fillStyle = "#ffffff";
  compositionCtx.fillRect(0, 0, compositionCanvas.width, compositionCanvas.height);
  compositionCtx.imageSmoothingEnabled = true;
  compositionCtx.drawImage(
    image,
    appState.newimageleft || 0,
    appState.newimagetop || 0,
    filewvalue,
    filehvalue
  );

  const faceCanvas = document.createElement("canvas");
  faceCanvas.width = faceWidth;
  faceCanvas.height = faceHeight;

  const faceCtx = faceCanvas.getContext("2d");
  if (!faceCtx) {
    throw new Error("Unable to create front-face canvas for mirror wrap");
  }

  faceCtx.drawImage(
    compositionCanvas,
    edgeSize,
    edgeSize,
    faceWidth,
    faceHeight,
    0,
    0,
    faceWidth,
    faceHeight
  );

  canvasnewblack.width = Math.max(1, Math.round(appState.newCanvasWidth));
  canvasnewblack.height = Math.max(1, Math.round(appState.newCanvasHeight));

  ctx1.clearRect(0, 0, canvasnewblack.width, canvasnewblack.height);
  ctx1.fillStyle = "#ffffff";
  ctx1.fillRect(0, 0, canvasnewblack.width, canvasnewblack.height);
  ctx1.imageSmoothingEnabled = true;

  drawMirroredEdgeStrips(ctx1, faceCanvas, edgeSize, 0, 0, true);

  return uploadRenderedEdgeCanvas(canvasnewblack, "canvas-with-mirror-edge.jpeg");
}

window.generateCanvasWithMirrorEdge = generateCanvasWithMirrorEdge;

async function generateCanvasWithWhiteEdge() {

  // Enhanced image loading function that handles all source types
  const loadImageFromSource = async (source) => {
    return new Promise((resolve, reject) => {
      // Case 1: Already an HTMLImageElement
      if (source instanceof HTMLImageElement) {
        if (source.complete && source.naturalHeight !== 0) {
          resolve(source);
        } else {
          source.onload = () => {
            resolve(source);
          };
          source.onerror = (e) => {
            console.error("HTMLImageElement load error:", e);
            reject(new Error('Failed to load image element'));
          };
        }
        return;
      }

      // Case 2: String (URL, base64, or blob URL)
      if (typeof source === 'string') {
        
        // Check if it's a data URL (base64)
        if (source.startsWith('data:')) {
          const img = new Image();
          img.onload = () => {
            resolve(img);
          };
          img.onerror = (e) => {
            console.error("Data URL image load error:", e);
            reject(new Error('Failed to load data URL image'));
          };
          img.src = source;
          return;
        }
        
        // Check if it's a blob URL
        if (source.startsWith('blob:')) {
          const img = new Image();
          img.onload = () => {
            resolve(img);
          };
          img.onerror = (e) => {
            console.error("Blob URL image load error:", e);
            reject(new Error('Failed to load blob URL image'));
          };
          img.src = source;
          return;
        }
        
        const img = new Image();
        
        // Important: Set crossOrigin for external URLs
        img.crossOrigin = "anonymous";
        
        img.onload = () => {
          resolve(img);
        };
        
        img.onerror = (e) => {
          console.error("External image load error:", e);
          console.error("Failed to load URL:", source);
          
          const fallbackImg = new Image();
          fallbackImg.onload = () => {
            resolve(fallbackImg);
          };
          fallbackImg.onerror = (fallbackError) => {
            console.error("Fallback also failed:", fallbackError);
            reject(new Error(`Failed to load image from URL: ${source}`));
          };
          fallbackImg.src = source;
        };
        
        img.src = source;
        return;
      }

      // Case 3: File or Blob object
      if (source instanceof File || source instanceof Blob) {
        const reader = new FileReader();
        reader.onload = function(e) {
          const img = new Image();
          img.onload = () => {
            resolve(img);
          };
          img.onerror = (e) => {
            console.error("File/Blob image load error:", e);
            reject(new Error('Failed to load file/blob image'));
          };
          img.src = e.target.result;
        };
        reader.onerror = (e) => {
          console.error("FileReader error:", e);
          reject(new Error('Failed to read file'));
        };
        reader.readAsDataURL(source);
        return;
      }

      // Case 4: Canvas element
      if (source instanceof HTMLCanvasElement) {
        const img = new Image();
        img.onload = () => {
          resolve(img);
        };
        img.onerror = (e) => {
          console.error("Canvas image load error:", e);
          reject(new Error('Failed to load canvas image'));
        };
        img.src = source.toDataURL();
        return;
      }

      // Case 5: If it's an object with src, url, or imageUrl property
      if (source && typeof source === 'object') {
        
        // Check for common image source properties
        let imageUrl = null;
        
        if (source.src) {
          imageUrl = source.src;
        } else if (source.url) {
          imageUrl = source.url;
        } else if (source.imageUrl) {
          imageUrl = source.imageUrl;
        } else if (source.data) {
          imageUrl = source.data;
        } else if (source.image) {
          imageUrl = source.image;
        } else if (source.link) {
          imageUrl = source.link;
        }
        
        if (imageUrl) {
          loadImageFromSource(imageUrl).then(resolve).catch(reject);
          return;
        }
        
        // Check if it's an object that can be converted to data URL
        if (source.toDataURL) {
          try {
            const dataUrl = source.toDataURL();
            loadImageFromSource(dataUrl).then(resolve).catch(reject);
            return;
          } catch (e) {
            console.error("Error converting object to data URL:", e);
          }
        }
      }

      // Case 6: If it's an object that might contain the actual image data
      // Try to stringify and see if it contains a URL
      if (source && typeof source === 'object') {
        const stringified = JSON.stringify(source);
        
        // Look for URL patterns in the stringified object
        const urlRegex = /(https?:\/\/[^\s"]+\.(png|jpg|jpeg|gif|webp))/i;
        const match = stringified.match(urlRegex);
        
        if (match) {
          const foundUrl = match[0];
          loadImageFromSource(foundUrl).then(resolve).catch(reject);
          return;
        }
      }

      try {
        const img = new Image();
        img.onload = () => {
          resolve(img);
        };
        img.onerror = (e) => {
          console.error("Unknown source type load failed:", e);
          reject(new Error(`Unsupported image source type: ${typeof source}`));
        };
        
        // Try to set src directly (might work for some object types)
        if (source instanceof Object) {
          // If it has a toString method, use it
          img.src = source.toString();
        } else {
          img.src = source;
        }
      } catch (finalError) {
        console.error("Final attempt failed:", finalError);
        reject(new Error(`Unsupported image source type: ${typeof source}. Object details: ${JSON.stringify(source)}`));
      }
    });
  };

  updatePositionInfo();

  // Use the main uploaded image or the black edge specific image
  const imageSource = appState.uploadedImageForBlackEdge || appState.uploadedImage;

  if (!imageSource) {
    alert("Please upload an image first!");
    throw new Error("No image source found");
  }

  if (!appState.newCanvasWidth || !appState.newCanvasHeight) {
    alert("Canvas dimensions not calculated. Please position the image first.");
    throw new Error("Canvas dimensions not calculated");
  }

  // Set canvas size
  canvasnewblack.width = appState.newCanvasWidth;
  canvasnewblack.height = appState.newCanvasHeight;

  // Fill background
  ctx1.fillStyle = "#fff";
  ctx1.fillRect(0, 0, canvasnewblack.width, canvasnewblack.height);

  // Helper function to convert base64 to blob
  const base64ToBlob = (base64Data) => {
    const parts = base64Data.split(';base64,');
    const contentType = parts[0].split(':')[1];
    const raw = window.atob(parts[1]);
    const uInt8Array = new Uint8Array(raw.length);
    
    for (let i = 0; i < raw.length; ++i) {
      uInt8Array[i] = raw.charCodeAt(i);
    }
    
    return new Blob([uInt8Array], { type: contentType });
  };

  // Helper function to get/set localStorage with 1-day expiry
  const getLocalStorage1Day = (key) => {
    try {
      const item = localStorage.getItem(key);
      if (!item) return null;
      
      // Check if it's already a JSON string with expiry
      if (item.startsWith('{') && item.includes('"expiry"')) {
        const { value, expiry } = JSON.parse(item);
        if (Date.now() > expiry) {
          localStorage.removeItem(key);
          return null;
        }
        return value;
      } else {
        // It's a regular string, return as-is
        return item;
      }
    } catch (error) {
      console.error('Error reading from localStorage:', error);
      // Return the raw item if parsing fails
      return localStorage.getItem(key);
    }
  };

  // Function to upload to image-thumbnail API (similar to exportFullDivAsImage)
  const uploadToThumbnailAPI = async ( cloudfrontLink ,customerId, sessionId) => {
    try {
      // let blob;
      // if (imageData.startsWith("data:")) {
      //   const res = await fetch(imageData);
      //   blob = await res.blob();
      // } else {
      //   // If it's already a blob or file
      //   blob = imageData;
      // }

      const formData = new FormData();
      // formData.append("file", blob, "full-div-image.jpeg");
      formData.append("customerId", customerId);
      formData.append("sessionId", sessionId);
      formData.append("thumbnailWidth", "200");
      formData.append("imageUrl", cloudfrontLink);

      const response = await fetch(`${window.Prompt2Prints.apiBase}/image-thumbnail`, {
        method: "POST",
              headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Thumbnail API responded with status: ${response.status}`);
      }

      const data = await response.json();

      // Store thumbnail URLs
      const hiddenInput = document.getElementById("preview-image-data");
      if (hiddenInput && data.original?.cloudfrontUrl) {
        hiddenInput.value = data.original.cloudfrontUrl;
      }

      const hiddenInput1 = document.getElementById("preview-thumb-image-data");
      if (hiddenInput1 && data.thumbnail?.cloudfrontUrl) {
        hiddenInput1.value = data.thumbnail.cloudfrontUrl;
      }

      return data;
    } catch (error) {
      console.error("❌ Thumbnail API upload failed:", error);
      throw error;
    }
  };

  try {
    

    const image = await loadImageFromSource(imageSource);
   
    // Get dimensions from UI or use image natural dimensions as fallback
    const filewvalue = parseFloat(document.getElementById("img-file-w")?.textContent) || image.naturalWidth || 0;
    const filehvalue = parseFloat(document.getElementById("img-file-h")?.textContent) || image.naturalHeight || 0;
    
    appState.imageWidth = filewvalue;
    appState.imageheight = filehvalue;
    
   
    // Clear and redraw background (in case image loading took time)
    ctx1.fillStyle = "#fff";
    ctx1.fillRect(0, 0, canvasnewblack.width, canvasnewblack.height);
    
    // Draw the image
    ctx1.drawImage(
      image,
      appState.newimageleft || 0,
      appState.newimagetop || 0,
      filewvalue,
      filehvalue
    );

    // Draw border
    ctx1.strokeStyle = "#fff";
    ctx1.lineWidth = (appState.newBorder || 10) * 2;
   
    ctx1.strokeRect(
      appState.newBorder || 5,
      appState.newBorder || 5,
      canvasnewblack.width - (appState.newBorder || 10) * 2,
      canvasnewblack.height - (appState.newBorder || 10) * 2
    );

    
    const uploadResult = await new Promise(async (resolve, reject) => {
      try {
        canvasnewblack.toBlob(async function(blob) {
          if (!blob) {
            reject(new Error('Failed to create blob from canvas'));
            return;
          }
          
          const file = new File([blob], "canvas-with-white-edge.jpeg", { type: "image/jpeg" });
  
          const link = document.createElement('a');
          link.download = file.name;
          link.href = URL.createObjectURL(file);
         
          link.click();
          URL.revokeObjectURL(link.href);
          
         
          try {
            const formData = new FormData();
            const userId = window.shopifyCustomerId || "guest";
            const sessionId = getLocalStorage1Day("sessionId") || "none";

            // Convert canvas to data URL for API upload
            const imageData = canvasnewblack.toDataURL("image/jpeg");
            
            if (imageData.startsWith("http") || imageData.startsWith("//")) {
              formData.append("imageUrl", imageData);
            } else if (imageData.startsWith("data:image/")) {
              const imageBlob = base64ToBlob(imageData);
              formData.append("file", imageBlob, "uploaded-image.jpeg");
            } else {
              reject(new Error("Invalid image data format"));
              return;
            }

            formData.append("customerId", userId);
            formData.append("sessionId", sessionId);

            const response = await fetch(`${window.Prompt2Prints.apiBase}/upload-image`, {
              method: "POST",
              headers: {
        "x-api-key": window.Prompt2Prints.apiKey
      },
              body: formData,
            });
            
            if (!response.ok) {
              throw new Error(`Main API responded with status: ${response.status}`);
            }
            
            const data = await response.json();
  const imageUpscale = document.querySelector('input[name="properties[_pdp-allow-upscale]"]');
const imageUpscaletag = document.querySelector('input[name="properties[_pdp-img-tag]"]');

if (!imageUpscale || !imageUpscaletag) {
  console.warn("Upscale inputs not found");
  return;
}

const flag = (data.flag || "").toLowerCase();

if (flag === "standard") {
  imageUpscale.value = "true";
  imageUpscaletag.value = "Standard";
} 
else if (flag === "professional") {
  imageUpscale.value = "false";
  imageUpscaletag.value = "Professional";
} 
else {
  imageUpscale.value = "";
  imageUpscaletag.value = "";
}

// Optional: also update attribute for Shopify forms
imageUpscale.setAttribute("value", imageUpscale.value);
imageUpscaletag.setAttribute("value", imageUpscaletag.value);

            let cloudfrontLink = null;
            let thumbnailData = null;

            // Store the CloudFront link from main API
            if (data.cloudfrontLink) {
              cloudfrontLink = data.cloudfrontLink;
              
              const hiddenInput = document.getElementById("final-image-data");
              if (hiddenInput) {
                hiddenInput.value = cloudfrontLink;
              
              } else {
                console.warn("❌ Hidden input with id 'final-image-data' not found");
              }
              
              const cvswElement = parseFloat(document.getElementById("cvs-w")?.textContent) || 0;
              const cvshElement = parseFloat(document.getElementById("cvs-h")?.textContent) || 0;
              const cvsimgwElement =  appState.newCanvasWidth;
              const cvsimghElement =  appState.newCanvasWidth;
              const hiddenimg = document.getElementById("frame-img-position");
                 const orientationRadio = document.querySelector('input[name="orientation"]:checked');
    const orientation = orientationRadio ? orientationRadio.value : "portrait";

    if(orientation == "portrait"){
        if (hiddenimg) {
                hiddenimg.value = JSON.stringify({
                  area_width: cvswElement,
                  area_height: cvshElement,
                  width: appState.newCanvasWidth,
                  height: appState.newCanvasHeight,
                  top: 0,
                  left: 0,
                });
              }
    }
    else if(orientation == "landscape"){
      if (hiddenimg) {
                hiddenimg.value = JSON.stringify({
                  area_width: cvshElement,
                  area_height: cvswElement,
                  width: appState.newCanvasHeight,
                  height:appState.newCanvasWidth,
                  top: 0,
                  left: 0,
                });
              }
    }
              // Also store in appState for easy access
              appState.generatedImageUrl = cloudfrontLink;
  
            } else {
              console.warn("❌ No cloudfrontLink in main API response");
            }

            try {
              thumbnailData = await uploadToThumbnailAPI(cloudfrontLink, userId, sessionId);
           
            } catch (thumbnailError) {
              console.error("❌ Thumbnail API upload failed, but continuing:", thumbnailError);
              // Don't reject here, as main upload was successful
            }

            resolve({ 
              success: true, 
              cloudfrontLink: cloudfrontLink,
              thumbnailData: thumbnailData,
              mainApiData: data
            });
            
          } catch (apiError) {
            console.error("❌ API upload failed:", apiError);
            reject(apiError);
          }
        }, 'image/jpeg');
      } catch (blobError) {
        console.error("Error creating blob:", blobError);
        reject(blobError);
      }
    });


    return uploadResult;

  } catch (error) {
    console.error('Error in generateCanvasWithWhiteEdge:', error);
    throw error; // Re-throw to be caught by the parent function
  }
}

// Make the function globally accessible
window.generateCanvasWithWhiteEdge = generateCanvasWithWhiteEdge;

document.addEventListener("DOMContentLoaded", function () {
  const items = document.querySelectorAll(".pdp-option-main-wrap");

  items.forEach(item => {
    const header = item.querySelector(".pdp-option-title-wrap.is-layout");
    const content = item.querySelector(".orientation-options");
    const arrow = item.querySelector(".pdp-option-arrow");

    if (!header || !content) return;

    content.style.display = "none";

    // Default open
    if (item.classList.contains("default-open")) {
      item.classList.add("active");
      header.setAttribute("aria-expanded", "true");
      content.style.display = "grid";
      if (arrow) arrow.style.transform = "rotate(180deg)";
    }

    header.addEventListener("click", () => {
      const expanded = header.getAttribute("aria-expanded") === "true";

      item.classList.toggle("active");
      header.setAttribute("aria-expanded", !expanded);

      if (expanded) {
        content.style.display = "none";
        if (arrow) arrow.style.transform = "rotate(0deg)";
      } else {
        content.style.display = "grid";
        if (arrow) arrow.style.transform = "rotate(180deg)";
      }
    });
  });
});


document.addEventListener("DOMContentLoaded", function () {
  const items = document.querySelectorAll(".frame-sizes");

  items.forEach(item => {
    const header = item.querySelector(".pdp-option-title-wrap.is-size");
    const content = item.querySelector(".frame-size-options");
    const arrow = item.querySelector(".pdp-option-arrow");

    if (!header || !content) return;

    content.style.display = "none";

    // Default open
    if (item.classList.contains("default-open")) {
      item.classList.add("active");
      header.setAttribute("aria-expanded", "true");
      content.style.display = "flex";
      if (arrow) arrow.style.transform = "rotate(180deg)";
    }

    header.addEventListener("click", () => {
      const expanded = header.getAttribute("aria-expanded") === "true";

      item.classList.toggle("active");
      header.setAttribute("aria-expanded", !expanded);

      if (expanded) {
        content.style.display = "none";
        if (arrow) arrow.style.transform = "rotate(0deg)";
      } else {
        content.style.display = "flex";
        if (arrow) arrow.style.transform = "rotate(180deg)";
      }
    });
  });
});


// Helper functions that were missing
function getLocalStorage1Day(key) {
  try {
    const item = localStorage.getItem(key);
    if (!item) return null;
    
    // Check if the item is already a JSON string with expiry
    if (item.startsWith('{') && item.includes('"expiry"')) {
      const { value, expiry } = JSON.parse(item);
      
      // Check if the item has expired
      if (Date.now() > expiry) {
        localStorage.removeItem(key);
        return null;
      }
      
      return value;
    } else {
      // It's a regular string, return as-is
      return item;
    }
  } catch (error) {
    console.error('Error reading from localStorage:', error);
    // Return the raw item if parsing fails
    return item;
  }
}
function setLocalStorage1Day(key, value) {
  try {
    // Set expiry to 1 day from now
    const expiry = Date.now() + (24 * 60 * 60 * 1000);
    const item = JSON.stringify({ value, expiry });
    localStorage.setItem(key, item);
  } catch (error) {
    console.error('Error writing to localStorage:', error);
  }
}

// Initialize any missing appState properties
if (!appState.uploadedImageForBlackEdge) {
  appState.uploadedImageForBlackEdge = null;
}


function updateCropButtonState() {
  const cropBtn = document.getElementById("crop-toggle-image");
  if (!cropBtn) return;

  const isCropped = Boolean(appState.cropState?.isCropped);
  const isSelecting = Boolean(appState.cropState?.isSelecting);
  cropBtn.classList.toggle("active", isCropped || isSelecting);
  cropBtn.setAttribute(
    "title",
    isSelecting ? "Apply crop" : (isCropped ? "Show full image" : "Crop image")
  );
}

function getClipBounds() {
  if (appState.clipPath && typeof appState.clipPath.getBoundingRect === "function") {
    return appState.clipPath.getBoundingRect(true);
  }

  if (appState.innerCanvas && typeof appState.innerCanvas.getBoundingRect === "function") {
    return appState.innerCanvas.getBoundingRect(true);
  }

  const canvasWidth = typeof canvas?.getWidth === "function" ? canvas.getWidth() : canvas?.width;
  const canvasHeight = typeof canvas?.getHeight === "function" ? canvas.getHeight() : canvas?.height;
  if (!Number.isFinite(canvasWidth) || !Number.isFinite(canvasHeight)) {
    return null;
  }

  const innerWidth = Number(appState.innerWidth);
  const innerHeight = Number(appState.innerHeight);
  if (Number.isFinite(innerWidth) && Number.isFinite(innerHeight) && innerWidth > 0 && innerHeight > 0) {
    return {
      left: (canvasWidth - innerWidth) / 2,
      top: (canvasHeight - innerHeight) / 2,
      width: innerWidth,
      height: innerHeight
    };
  }

  const padding = Number(appState.innerPadding ?? appState.borderSize ?? 0);
  if (Number.isFinite(padding) && padding >= 0 && canvasWidth > padding * 2 && canvasHeight > padding * 2) {
    return {
      left: padding,
      top: padding,
      width: canvasWidth - padding * 2,
      height: canvasHeight - padding * 2
    };
  }

  return null;
}

function cleanupCropSelection() {
  const selectionRect = appState.cropState?.selectionRect;
  if (selectionRect) {
    canvas.remove(selectionRect);
  }
  appState.cropState.selectionRect = null;
  appState.cropState.isSelecting = false;
}

function setImageInteractionEnabled(enabled) {
  const img = appState.uploadedImage;
  if (!img) return;

  img.set({
    selectable: enabled,
    evented: enabled
  });
}

function clampCropSelectionToImage(selectionRect, img) {
  if (!selectionRect || !img) return;

  const imgBounds = img.getBoundingRect(true);
  if (!imgBounds || !imgBounds.width || !imgBounds.height) return;

  let nextScaleX = selectionRect.scaleX || 1;
  let nextScaleY = selectionRect.scaleY || 1;

  const currentW = selectionRect.width * nextScaleX;
  const currentH = selectionRect.height * nextScaleY;

  if (currentW > imgBounds.width) {
    nextScaleX = imgBounds.width / selectionRect.width;
  }
  if (currentH > imgBounds.height) {
    nextScaleY = imgBounds.height / selectionRect.height;
  }

  selectionRect.set({
    scaleX: nextScaleX,
    scaleY: nextScaleY
  });

  const halfW = selectionRect.getScaledWidth() / 2;
  const halfH = selectionRect.getScaledHeight() / 2;

  const minLeft = imgBounds.left + halfW;
  const maxLeft = imgBounds.left + imgBounds.width - halfW;
  const minTop = imgBounds.top + halfH;
  const maxTop = imgBounds.top + imgBounds.height - halfH;

  selectionRect.set({
    left: Math.min(Math.max(selectionRect.left, minLeft), maxLeft),
    top: Math.min(Math.max(selectionRect.top, minTop), maxTop)
  });

  selectionRect.setCoords();
}

function startInteractiveCrop() {
  const img = appState.uploadedImage;
  if (!img) return;

  cleanupCropSelection();

  const imgBounds = img.getBoundingRect(true);
  const clipBounds = getClipBounds();
  const defaultBounds = clipBounds || imgBounds;

  const intersectLeft = Math.max(imgBounds.left, defaultBounds.left);
  const intersectTop = Math.max(imgBounds.top, defaultBounds.top);
  const intersectRight = Math.min(imgBounds.left + imgBounds.width, defaultBounds.left + defaultBounds.width);
  const intersectBottom = Math.min(imgBounds.top + imgBounds.height, defaultBounds.top + defaultBounds.height);

  const initialLeft = intersectRight > intersectLeft ? intersectLeft : imgBounds.left;
  const initialTop = intersectBottom > intersectTop ? intersectTop : imgBounds.top;
  const initialWidth = intersectRight > intersectLeft ? (intersectRight - intersectLeft) : imgBounds.width;
  const initialHeight = intersectBottom > intersectTop ? (intersectBottom - intersectTop) : imgBounds.height;

  const selectionRect = new fabric.Rect({
    left: initialLeft + initialWidth / 2,
    top: initialTop + initialHeight / 2,
    originX: "center",
    originY: "center",
    width: initialWidth,
    height: initialHeight,
    fill: "rgba(0,0,0,0.08)",
    stroke: "#111111",
    strokeWidth: 1,
    strokeDashArray: [6, 4],
    selectable: true,
    evented: true,
    hasBorders: true,
    hasControls: true,
    lockRotation: true,
    transparentCorners: false,
    cornerColor: "#ffffff",
    cornerStrokeColor: "#111111",
    borderColor: "#111111",
    cornerSize: 10
  });

  selectionRect.setControlsVisibility({
    mtr: false
  });

  const enforceBounds = () => {
    clampCropSelectionToImage(selectionRect, img);
    canvas.requestRenderAll();
  };

  selectionRect.on("moving", enforceBounds);
  selectionRect.on("scaling", enforceBounds);
  selectionRect.on("modified", enforceBounds);

  canvas.add(selectionRect);
  canvas.setActiveObject(selectionRect);
  canvas.bringToFront(selectionRect);

  appState.cropState.selectionRect = selectionRect;
  appState.cropState.isSelecting = true;
  setImageInteractionEnabled(false);
  updateCropButtonState();
  canvas.requestRenderAll();
}

function applyInteractiveCrop() {
  const img = appState.uploadedImage;
  const selectionRect = appState.cropState?.selectionRect;
  if (!img || !selectionRect) return;

  const imgBounds = img.getBoundingRect(true);
  const selBounds = selectionRect.getBoundingRect(true);

  const intersectLeft = Math.max(imgBounds.left, selBounds.left);
  const intersectTop = Math.max(imgBounds.top, selBounds.top);
  const intersectRight = Math.min(imgBounds.left + imgBounds.width, selBounds.left + selBounds.width);
  const intersectBottom = Math.min(imgBounds.top + imgBounds.height, selBounds.top + selBounds.height);

  if (intersectRight <= intersectLeft || intersectBottom <= intersectTop || !img.scaleX || !img.scaleY) {
    return;
  }

  if (!appState.cropState.isCropped) {
    appState.cropState.backup = {
      cropX: img.cropX || 0,
      cropY: img.cropY || 0,
      width: img.width,
      height: img.height,
      left: img.left,
      top: img.top,
      scaleX: img.scaleX,
      scaleY: img.scaleY
    };
  }

  const visibleW = intersectRight - intersectLeft;
  const visibleH = intersectBottom - intersectTop;

  const nextCropX = (img.cropX || 0) + (intersectLeft - imgBounds.left) / img.scaleX;
  const nextCropY = (img.cropY || 0) + (intersectTop - imgBounds.top) / img.scaleY;

  img.set({
    cropX: nextCropX,
    cropY: nextCropY,
    width: visibleW / img.scaleX,
    height: visibleH / img.scaleY,
    left: intersectLeft + visibleW / 2,
    top: intersectTop + visibleH / 2
  });

  appState.cropState.isCropped = true;
  cleanupCropSelection();
  setImageInteractionEnabled(true);
  canvas.setActiveObject(img);
}

function toggleImageCrop() {
  const img = appState.uploadedImage;
  if (!img) return;

  if (img.angle && Math.abs(img.angle % 360) !== 0) {
    alert("Please reset image rotation before using crop.");
    return;
  }

  if (appState.cropState.isSelecting) {
    applyInteractiveCrop();
  } else if (!appState.cropState.isCropped) {
    startInteractiveCrop();
  } else {
    const backup = appState.cropState.backup;
    if (!backup) return;

    img.set({
      cropX: backup.cropX,
      cropY: backup.cropY,
      width: backup.width,
      height: backup.height,
      left: backup.left,
      top: backup.top,
      scaleX: backup.scaleX,
      scaleY: backup.scaleY
    });

    appState.cropState.isCropped = false;
    appState.cropState.backup = null;
    setImageInteractionEnabled(true);
    canvas.setActiveObject(img);
  }

  img.setCoords();
  updateMovementConstraints();
  updatePositionInfo();
  canvas.requestRenderAll();
  updateCropButtonState();
}




function setWrap(){
  value = sessionStorage.getItem("selectedWrap");
  if (!value) return;

  if (value === "black") {
    appState.baseEdgeType = "BlackWrap";
    syncSelectedEdgeType();
    coverFrame("black");
  }
  else if (value === "white") {
    appState.baseEdgeType = "WhiteWrap";
    syncSelectedEdgeType();
    coverFrame("white");
  }
  else if (value === "fit") {
    appState.baseEdgeType = "FitToEdge";
    syncSelectedEdgeType();
     // fitImageToFrame(true);
     FitFrontFrame();
  }
}


document.getElementById("fill-front-image").addEventListener("click", () => {
 coverFrame1();
  updatePositionInfo();
});
document.getElementById("fill-side-image").addEventListener("click", () => {
 fitImageToFrame(true);
 updatePositionInfo();
});
document.getElementById("fit-front-image").addEventListener("click", () => {
 FitFrontFrame();
  updatePositionInfo();
});

document.getElementById("center-image").addEventListener("click", () => {
  centerImage();
  updatePositionInfo();
});

const cropToggleBtn = document.getElementById("crop-toggle-image");
if (cropToggleBtn) {
  cropToggleBtn.addEventListener("click", () => {
    toggleImageCrop();
  });
}

updateCropButtonState();

window.getLocalStorage1Day = getLocalStorage1Day;
window.setLocalStorage1Day = setLocalStorage1Day;
window.appState = appState;

document.querySelector('.frm-note-close').addEventListener('click', () => {
  document.querySelector('.frm-image-note').style.display = 'none';
});
