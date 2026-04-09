
if (window.fabric) {
    fabric.Object.prototype.hasControls = false;
    fabric.Object.prototype.hasBorders = false;
  }

const canvas = new fabric.Canvas("image-canvas");

// ============================================
// 3D PREVIEW SCHEDULING
// ============================================
let p2p3dPreviewUpdateTimer = null;
let p2p3dPreviewLastDispatchAt = 0;
const P2P_3D_PREVIEW_THROTTLE_MS = 120;

function is3DPreviewEnabled() {
  const toggle = document.getElementById("toggleSplit");
  if (!toggle || !toggle.checked) return false;
  return true;
}

function schedule3DPreviewUpdate() {
  if (!is3DPreviewEnabled()) return;

  if (p2p3dPreviewUpdateTimer) return;

  const now = Date.now();
  const elapsed = now - (p2p3dPreviewLastDispatchAt || 0);
  const delay = Math.max(0, P2P_3D_PREVIEW_THROTTLE_MS - elapsed);

  p2p3dPreviewUpdateTimer = setTimeout(() => {
    p2p3dPreviewUpdateTimer = null;
    p2p3dPreviewLastDispatchAt = Date.now();

    try {
      if (typeof window.updateThreeDPreview === "function") {
        window.updateThreeDPreview();
        return;
      }

      if (window.Canvas3DPreview && typeof window.Canvas3DPreview.updateThreePreview === "function") {
        window.Canvas3DPreview.updateThreePreview();
        return;
      }

      window.dispatchEvent(new CustomEvent("p2p:canvas-preview-update"));
    } catch (error) {
      // ignore
    }
  }, delay);
}

const appState = {
  outerMargin: 0,
  innerPadding: 10,
  innerWidth: 400,
  innerHeight: 400,
  selectedWidth: 400,
  selectedHeight: 40,
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
  canvasBorderColor: "#ffffff",
  canvasWidth: 0,
  canvasHeight: 0,
  newCanvasWidth: 0,
  newCanvasHeight: 0,
  frameColor: "#000",
  imageFinall: 0,
  imageFinalt: 0,
  imageFinalh: 0,
  imageFinalW: 0,
  imageWidth: 0,
  imageHeight: 0,
  newimageleft: 0,
  newimagetop: 0,
  border: 0,
  selectedEdgeType: "FitToEdge",
};

// ============================================
// HEIC/HEIF CONVERSION SUPPORT (for Chrome & non-Apple browsers)
// ============================================
let _pdpV4Heic2AnyLoaded = false;
let _pdpV4Heic2AnyLoading = false;
let _pdpV4Heic2AnyLoadPromise = null;

function pdpV4LoadHeic2Any() {
  if (_pdpV4Heic2AnyLoaded && window.heic2any) return Promise.resolve();
  if (_pdpV4Heic2AnyLoading && _pdpV4Heic2AnyLoadPromise) return _pdpV4Heic2AnyLoadPromise;

  _pdpV4Heic2AnyLoading = true;
  _pdpV4Heic2AnyLoadPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://cdn.jsdelivr.net/npm/heic2any@0.0.4/dist/heic2any.min.js";
    script.onload = () => {
      _pdpV4Heic2AnyLoaded = true;
      _pdpV4Heic2AnyLoading = false;
      resolve();
    };
    script.onerror = () => {
      _pdpV4Heic2AnyLoading = false;
      reject(new Error("Failed to load heic2any library"));
    };
    document.head.appendChild(script);
  });

  return _pdpV4Heic2AnyLoadPromise;
}

function pdpV4IsHeicFile(file) {
  if (!file) return false;
  const type = (file.type || "").toLowerCase();
  const name = (file.name || "").toLowerCase();
  return (
    type === "image/heic" ||
    type === "image/heif" ||
    name.endsWith(".heic") ||
    name.endsWith(".heif")
  );
}

function pdpV4ReplaceExtension(filename, newExtWithDot) {
  const name = String(filename || "image").trim() || "image";
  const lastDot = name.lastIndexOf(".");
  if (lastDot <= 0) return `${name}${newExtWithDot}`;
  return `${name.slice(0, lastDot)}${newExtWithDot}`;
}

async function pdpV4ConvertHeicToJpeg(file) {
  await pdpV4LoadHeic2Any();
  if (!window.heic2any) throw new Error("heic2any library not available after loading");

  const outputBlob = await window.heic2any({
    blob: file,
    toType: "image/jpeg",
    quality: 0.92
  });

  const resultBlob = Array.isArray(outputBlob) ? outputBlob[0] : outputBlob;
  const blobUrl = URL.createObjectURL(resultBlob);

  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(resultBlob);
  });

  const jpegName = pdpV4ReplaceExtension(file?.name, ".jpg");
  const jpegFile = new File([resultBlob], jpegName, { type: "image/jpeg" });

  return { blobUrl, blob: resultBlob, dataUrl, file: jpegFile };
}

// ===========================================
// PINCH TO ZOOM FUNCTIONALITY FOR MOBILE
// ===========================================
// Variables for pinch zoom
let initialDistance = 0;
let initialZoom = 1;
let lastCenter = { x: 0, y: 0 };
let isPinching = false;
let lastTouchTime = 0;
let pinchEndCooldownUntil = 0;

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
    initialZoom = getCurrentImageZoom();
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
    const requestedPinchZoom = Math.max(
      appState.minZoom,
      Math.min(appState.maxZoom, initialZoom * zoomFactor)
    );
    const clampedPinchZoom = clampZoomByDpi(requestedPinchZoom, MIN_PRINT_DPI);
    const baseScale = getBaseScale();
    const dpiSafeScale = baseScale > 0 ? (baseScale * clampedPinchZoom) : appState.uploadedImage.scaleX;
    
    // Get canvas center in screen coordinates
    const canvasRect = canvas.getElement().getBoundingClientRect();
    // Calculate translation (panning during pinch)
    const deltaX = currentCenter.x - lastCenter.x;
    const deltaY = currentCenter.y - lastCenter.y;
    
    // Apply zoom with pivot at touch center
    const oldScale = appState.uploadedImage ? (appState.uploadedImage.scaleX || 1) : 1;
    appState.scaleFactor = dpiSafeScale;
    
    // Calculate the scale change
    const scaleChange = dpiSafeScale / oldScale;
    
    // Update the image scale
    if (appState.uploadedImage) {
      const img = appState.uploadedImage;
      
      // Convert touch center to canvas coordinates relative to image
      const canvasCoords = screenToCanvas(lastCenter.x, lastCenter.y);
      
      // Get current image position and dimensions
      const imgLeft = img.left;
      const imgTop = img.top;
      // Calculate new position to keep the pinch center point fixed
      const newLeft = canvasCoords.x - (canvasCoords.x - imgLeft) * scaleChange;
      const newTop = canvasCoords.y - (canvasCoords.y - imgTop) * scaleChange;
      
      // Apply new scale and position
      img.scaleX = dpiSafeScale;
      img.scaleY = dpiSafeScale;
      img.left = newLeft;
      img.top = newTop;
      
      // Also apply additional panning from finger movement
      img.left += deltaX / canvas.getZoom();
      img.top += deltaY / canvas.getZoom();
      
      img.setCoords();
    }
    appState.zoom = clampedPinchZoom;
    
    // Update center for next move
    lastCenter = currentCenter;
    
    // Update everything
    updateMovementConstraints();
    updatePositionInfo();
    syncZoomSlider();
    updateZoomControlsState();
    if (requestedPinchZoom > (clampedPinchZoom + 0.000001)) {
      showZoomLimitMessage();
    }
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
  const wasPinching = isPinching;
  if (isPinching) {
    isPinching = false;
    
    // Reset variables
    initialDistance = 0;
    initialZoom = 1;
    lastCenter = { x: 0, y: 0 };
    
    // Sync slider with current zoom
    syncZoomSlider();
    updateZoomControlsState();
    canvas.requestRenderAll();
    lastTouchTime = Date.now();
    pinchEndCooldownUntil = Date.now() + 350;
    return;
  }
  
  // Handle double tap for zoom reset
  if (wasPinching) {
    lastTouchTime = Date.now();
    pinchEndCooldownUntil = Date.now() + 350;
    return;
  }
  const currentTime = Date.now();
  if (currentTime < pinchEndCooldownUntil) {
    lastTouchTime = currentTime;
    return;
  }
  const timeDiff = currentTime - lastTouchTime;
  
  // if (timeDiff < 35 && e.touches.length === 0 && e.changedTouches.length === 1) {
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

canvas.wrapperEl.addEventListener('touchcancel', function() {
  isPinching = false;
  initialDistance = 0;
  initialZoom = 1;
  lastCenter = { x: 0, y: 0 };
  pinchEndCooldownUntil = Date.now() + 350;
});

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
  { x: 0.3545, y: 0.199, w: 0.295, h: 0.375 }, // mockup 1 
  { x: 0.382, y: 0.354, w: 0.23, h: 0.292 }, // mockup 2 
  { x: 0.373, y: 0.106, w: 0.104, h: 0.132 }, // mockup 3 
  { x: 0.376, y: 0.488, w: 0.246, h: 0.311 }, // mockup 4
];

const mockupState = {
  croppedWidth: 0,
  croppedHeight: 0
};

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

// 3D preview — fire on every canvas mutation
canvas.on("object:moving",   schedule3DPreviewUpdate);
canvas.on("object:modified", schedule3DPreviewUpdate);
canvas.on("object:added",    schedule3DPreviewUpdate);
canvas.on("object:removed",  schedule3DPreviewUpdate);
canvas.on("object:scaling",  schedule3DPreviewUpdate);
canvas.on("object:rotating", schedule3DPreviewUpdate);

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
    scale: (img.scaleX * 100)/ 100,
    angle: img.angle,
  };
}


function setMovementConstraints() {
  if (!appState.uploadedImage) return;
  
  const img = appState.uploadedImage;
  const width = img.getScaledWidth();
  const height = img.getScaledHeight();
  const isLandscape = width > height;
  const isPortrait = height > width;
  const isSquare = width === height;
  
  // if (isLandscape) {
  //   img.set({
  //     lockMovementX: false,
  //     lockMovementY: true
  //   });
  // } else if (isPortrait) {
  //   img.set({
  //     lockMovementX: true,
  //     lockMovementY: false
  //   });
  // } else {
  //   img.set({
  //     lockMovementX: false,
  //     lockMovementY: false
  //   });
  // }
  img.setCoords();
  canvas.requestRenderAll();
}

function updateMovementConstraints() {
  if (!appState.uploadedImage) return;
  
  const img = appState.uploadedImage;
  const width = img.getScaledWidth();
  const height = img.getScaledHeight(); 
  const isLandscape = width > height;
  const isPortrait = height > width;
  
  // if (isLandscape) {
  //   img.set({
  //     lockMovementX: false,
  //     lockMovementY: true
  //   });
  // } else if (isPortrait) {
  //   img.set({
  //     lockMovementX: true,
  //     lockMovementY: false
  //   });
  // } else {
  //   img.set({
  //     lockMovementX: false,
  //     lockMovementY: false
  //   });
  // }
  
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
  let resizeTimeout;
  window.addEventListener("resize", updateDisplay);
});

function updatePositionInfo() {
  const pos = getImagePosition();
  if (!pos) return;

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
  const imageratio = Number((imgwidth / imgheight).toFixed(2));
  const cvswElement = document.getElementById("cvs-w")?.textContent || 0;
  const cvshElement = document.getElementById("cvs-h")?.textContent || 0;
  const finalw = (imgwidth * rvalue);
  appState.imageFinalW = finalw;
  const finalh = (imgheight * rvalue);
  appState.imageFinalh = finalh;
  const finalt = (imgtop * rvalue);
  appState.imageFinalt = finalt;
  const finall = (imgleft * rvalue);
  appState.imageFinall = finall;

  const currentimgw = finalw / 96;
  const currentimgh = finalh / 96;

  const filewvalue = document.getElementById("img-file-w")?.textContent || 0;
  const filehvalue = document.getElementById("img-file-h")?.textContent || 0;

  const dpiW = filewvalue && currentimgw ? filewvalue / currentimgw : 0;
  const dpiH = filehvalue && currentimgh ? filehvalue / currentimgh : 0;
  const dpi = Math.round((dpiW + dpiH) / 2);

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
  updateZoomControlsState();
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

// const dpiElement = document.querySelector(".dpi-num");
// const iconElement = document.querySelector(".dpi-state-icon");
const boostBtn = document.querySelector(".boost-img-btn");
 boostBtn.style.display = "none"; 


function updateDpiDisplay() {

  // const dpiElement = document.querySelector(".dpi-num");
  // const iconElements = document.querySelectorAll(".dpi-state-icon");
  const boostBtn = document.querySelector(".boost-img-btn");
  const confirmBtn = document.querySelector(".image-conform-btn");

  const currentDpi = Number((appState.dpi || 0).toFixed(2));

  if ( !boostBtn) return;

  // Clear all icons first
  // iconElements.forEach(el => {
  //   el.innerHTML = "";
  // });

  if (currentDpi > 0 && currentDpi < 30) {
    // dpiElement.textContent = `Needs Upscale`;
    // dpiElement.style.color = "red";

    // iconElements.forEach(el => {
    //   el.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
    //   <path d="M9.9891 0C4.49317 0 0 4.49317 0 9.9891C0 15.4859 4.49317 20 9.9891 20C15.485 20 20 15.5068 20 9.9891C20 4.47115 15.5068 0 9.9891 0ZM9.9891 18.3208C5.40912 18.3208 1.67946 14.5911 1.67946 10.0111C1.67946 5.43115 5.40912 1.70148 9.9891 1.70148C14.5691 1.70148 18.2987 5.43115 18.2987 10.0111C18.3207 14.5911 14.5909 18.3208 9.9891 18.3208Z" fill="#FF0606"/>
    //   <path d="M10.1207 4.56252C9.74952 4.56252 9.44421 4.69326 9.20466 4.93365C8.98621 5.1732 8.85547 5.52239 8.85547 5.93651C8.85547 6.24185 8.8774 6.72177 8.92126 7.41931L9.16081 10.9307C9.20466 11.4106 9.29154 11.7379 9.37926 11.9774C9.48806 12.2389 9.70651 12.3696 10.0118 12.3696C10.3172 12.3696 10.5137 12.2389 10.6444 11.9774C10.7532 11.7379 10.841 11.3887 10.8629 10.9526L11.1682 7.33156C11.2121 7.0043 11.2121 6.65511 11.2121 6.34977C11.2121 5.78297 11.1463 5.34691 10.9936 5.04073C10.884 4.7371 10.5787 4.56252 10.1207 4.56252Z" fill="#FF0606"/>
    //   <path d="M10.0549 13.4844C9.72761 13.4844 9.44421 13.5932 9.20466 13.8336C8.96511 14.0731 8.85547 14.3354 8.85547 14.6627C8.85547 15.0338 8.9862 15.3391 9.2266 15.5348C9.46615 15.7313 9.75039 15.8402 10.0768 15.8402C10.3821 15.8402 10.6655 15.7313 10.9059 15.5129C11.1455 15.2944 11.277 14.6408 11.277 14.6408C11.277 14.3135 11.1682 14.0301 10.9278 13.7906C10.6655 13.5932 10.3813 13.4844 10.0549 13.4844Z" fill="#FF0606"/>
    // </svg>`;
    // });

    boostBtn.style.display = "flex";
    boostBtn.classList.add("show");

  } else if (currentDpi >= 30) {
//    dpiElement.textContent = `Good To Print`;
//     dpiElement.style.color = "green";

//     iconElements.forEach(el => {
//       el.innerHTML =`<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
// <path d="M10 0C4.48421 0 0 4.48421 0 10C0 15.5158 4.48421 20 10 20C15.5158 20 20 15.5158 20 10C20 4.48421 15.5158 0 10 0ZM10 17.8105C5.68421 17.8105 2.18947 14.2947 2.18947 10C2.18947 5.70526 5.68421 2.18947 10 2.18947C14.3158 2.18947 17.8105 5.68421 17.8105 10C17.8105 14.3158 14.3158 17.8105 10 17.8105Z" fill="#1B8600"/>
// <path d="M12.7139 6.92258L8.90337 10.7542L7.28232 9.13311C6.86127 8.71205 6.16653 8.71205 5.74548 9.13311C5.32442 9.55416 5.32442 10.2489 5.74548 10.6699L8.14548 13.0699C8.356 13.2805 8.62969 13.3857 8.92443 13.3857C9.21916 13.3857 9.49285 13.2805 9.70337 13.0699L14.2928 8.48047C14.7139 8.05942 14.7139 7.36469 14.2928 6.94363C13.8507 6.50153 13.156 6.50153 12.7139 6.92258Z" fill="#1B8600"/>
// </svg>`;

//     });

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

  const frnheight = appState.originalHeight;
  const frmwidth = appState.originalWidth;
  let size = `${frmwidth}x${frnheight}`;
  const sortedSize = [frmwidth, frnheight].sort((a, b) => a - b).join("x");

  let innerPadding;

  if (window.innerWidth < 680) {
    switch (sortedSize) {
      case "1056x1248": innerPadding = 144 / 6.24; break;
      case "1152x1440": innerPadding = 144 / 7.2; break;
      case "1344x1632": innerPadding = 144 / 8.16; break;
      case "1440x1440": innerPadding = 144 / 7.2; break;
      case "1440x1824": innerPadding = 144 / 9.12; break;
      case "1440x2016": innerPadding = 144 / 10.08; break;
      case "1824x1824": innerPadding = 144 / 9.12; break;
      case "1824x2208": innerPadding = 144 / 11.04; break;
      case "2016x2592": innerPadding = 144 / 12.96; break;
      case "2208x2976": innerPadding = 144 / 14.88; break;
      case "2208x3168": innerPadding = 144 / 15.84; break;
      case "2592x3360": innerPadding = 144 / 16.8; break;
      case "2592x3744": innerPadding = 144 / 18.72; break;
      default: innerPadding = null;
    }
  } else {
    switch (sortedSize) {
      case "1056x1248": innerPadding = 144 / 3.12; break;
      case "1152x1440": innerPadding = 144 / 3.6; break;
      case "1344x1632": innerPadding = 144 / 4.08; break;
      case "1440x1440": innerPadding = 144 / 3.6; break;
      case "1440x1824": innerPadding = 144 / 4.56; break;
      case "1440x2016": innerPadding = 144 / 5.04; break;
      case "1824x1824": innerPadding = 144 / 4.56; break;
      case "1824x2208": innerPadding = 144 / 5.52; break;
      case "2016x2592": innerPadding = 144 / 6.48; break;
      case "2208x2976": innerPadding = 144 / 7.44; break;
      case "2208x3168": innerPadding = 144 / 7.92; break;
      case "2592x3360": innerPadding = 144 / 8.4; break;
      case "2592x3744": innerPadding = 144 / 9.36; break;
      default: innerPadding = null;
    }
  }

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

  appState.borderSize = innerPadding;
  schedule3DPreviewUpdate();
  applyFrameClip();

  /* ================= STRIPE PATTERN HELPER ================= */
function createWrappedStripePattern(
  ctx,
  {
    stripeWidth = 20,
    stripeHeight = 1000,
    stripeGap = 20,
    angle = 45,
    stripeColor = "#c8c8c8",
    stripeOpacity = 1,
  } = {}
) {
  const tileSize = 400;

  const pCanvas = document.createElement("canvas");
  pCanvas.width = tileSize;
  pCanvas.height = tileSize;

  const pctx = pCanvas.getContext("2d");

  /* ================= BACKGROUND ================= */
const frmcolor =  appState.frameColor

  pctx.fillStyle = frmcolor;
  pctx.fillRect(0, 0, tileSize, tileSize);

  /* ================= ROTATION ================= */
  pctx.translate(tileSize / 2, tileSize / 2);
  pctx.rotate((angle * Math.PI) / 180);
  pctx.translate(-tileSize / 2, -tileSize / 2);


  /* ================= STRIPES ================= */
  if(frmcolor === "#000"){
    pctx.fillStyle = "#333";
    pctx.globalAlpha = 1;
  }
  else if(frmcolor === "#FFFFFF"){
    pctx.fillStyle = "#c8c8c8";
    pctx.globalAlpha = 0.5;
  }
  else{
   pctx.fillStyle = stripeColor;
   pctx.globalAlpha = 0.5;
  }

  for (
    let x = -tileSize;
    x <= tileSize * 2;
    x += stripeWidth + stripeGap
  ) {
    pctx.fillRect(
      x,
      (tileSize - stripeHeight) / 2,
      stripeWidth,
      stripeHeight
    );
  }

  pctx.globalAlpha = 1;

  return ctx.createPattern(pCanvas, "repeat");
}

function getFrameMetrics() {
  const ratioValue = Number(document.getElementById("r")?.textContent) || 1;
  // Round up to whole pixels to avoid hairline seams, then overdraw slightly when painting.
  const outerThickness = Math.ceil(65 / ratioValue); // constant black band
  const innerThickness = Math.ceil(43 / ratioValue); // user-selected color band
  const gapThickness   = Math.ceil(36 / ratioValue); // gap between frame and print
  const innerInset = outerThickness + innerThickness + gapThickness;

  const bw = canvas.getWidth();
  const bh = canvas.getHeight();
  const innerWidth = bw - innerInset * 2;
  const innerHeight = bh - innerInset * 2;

  return {
    ratioValue,
    outerThickness,
    innerThickness,
    gapThickness,
    innerInset,
    innerWidth,
    innerHeight,
    bw,
    bh,
  };
}

function shadeColor(hex, multiplier = 0.85) {
  const clean = (hex || "#000000").replace("#", "");
  const num = parseInt(clean.length === 3
    ? clean.split("").map((c) => c + c).join("")
    : clean, 16);
  const r = Math.max(0, Math.min(255, Math.round(((num >> 16) & 255) * multiplier)));
  const g = Math.max(0, Math.min(255, Math.round(((num >> 8) & 255) * multiplier)));
  const b = Math.max(0, Math.min(255, Math.round((num & 255) * multiplier)));
  return `rgb(${r}, ${g}, ${b})`;
}

function applyFrameClip() {
  if (typeof fabric === "undefined" || !canvas) return;

  const metrics = getFrameMetrics();
  const clipRect = new fabric.Rect({
    left: metrics.innerInset,
    top: metrics.innerInset,
    width: metrics.innerWidth,
    height: metrics.innerHeight,
    absolutePositioned: true,
  });

  appState.clipPath = clipRect;

  if (appState.uploadedImage) {
    appState.uploadedImage.clipPath = clipRect;
    appState.uploadedImage.setCoords();
    canvas.requestRenderAll();
  }
}

  function drawBorderOnTop() {
    const ctx = canvas.contextTop;
    if (!ctx) return;

    canvas.clearContext(canvas.contextTop);

    const {
      outerThickness,
      innerThickness,
      gapThickness,
      innerInset,
      bw,
      bh
    } = getFrameMetrics();
    const overdraw = 1; // cover tiny seams by overlapping bands

    ctx.save();

    /* ============ OUTER FRAME (constant black) ============ */
    ctx.fillStyle = "#000000";
    // top + bottom
    ctx.fillRect(0, 0, bw, outerThickness + overdraw);
    ctx.fillRect(0, bh - outerThickness - overdraw, bw, outerThickness + overdraw);
    // left + right
    ctx.fillRect(0, outerThickness, outerThickness + overdraw, bh - outerThickness * 2);
    ctx.fillRect(bw - outerThickness - overdraw, outerThickness, outerThickness + overdraw, bh - outerThickness * 2);

    /* ============ INNER FRAME (user-selected color) ============ */
    const innerFrameColor = appState.frameColor || "#000000";
    ctx.fillStyle = innerFrameColor;
    // top + bottom
    ctx.fillRect(outerThickness, outerThickness, bw - outerThickness * 2, innerThickness + overdraw);
    ctx.fillRect(
      outerThickness,
      bh - outerThickness - innerThickness - overdraw,
      bw - outerThickness * 2,
      innerThickness + overdraw
    );
    // left + right
    ctx.fillRect(
      outerThickness,
      outerThickness + innerThickness,
      innerThickness + overdraw,
      bh - 2 * (outerThickness + innerThickness)
    );
    ctx.fillRect(
      bw - outerThickness - innerThickness - overdraw,
      outerThickness + innerThickness,
      innerThickness + overdraw,
      bh - 2 * (outerThickness + innerThickness)
    );

    /* ============ GAP BETWEEN FRAME & PRINT ============ */
    const gapColor = shadeColor(innerFrameColor, 0.8); // subtle darker shade of frame color
    ctx.fillStyle = gapColor;
    // top + bottom gap bands
    ctx.fillRect(
      outerThickness + innerThickness,
      outerThickness + innerThickness,
      bw - (outerThickness + innerThickness) * 2,
      gapThickness + overdraw
    );
    ctx.fillRect(
      outerThickness + innerThickness,
      bh - (outerThickness + innerThickness + gapThickness) - overdraw,
      bw - (outerThickness + innerThickness) * 2,
      gapThickness + overdraw
    );
    // left + right gap bands
    ctx.fillRect(
      outerThickness + innerThickness,
      outerThickness + innerThickness + gapThickness,
      gapThickness + overdraw,
      bh - 2 * (outerThickness + innerThickness + gapThickness)
    );
    ctx.fillRect(
      bw - (outerThickness + innerThickness + gapThickness) - overdraw,
      outerThickness + innerThickness + gapThickness,
      gapThickness + overdraw,
      bh - 2 * (outerThickness + innerThickness + gapThickness)
    );

    /* ============ INNER OUTLINE (print area) ============ */
    ctx.strokeStyle = "#bfbfbf";
    ctx.lineWidth = 0.75;
    ctx.strokeRect(
      innerInset - 0.375,
      innerInset - 0.375,
      bw - innerInset * 2 + 0.75,
      bh - innerInset * 2 + 0.75
    );

    ctx.restore();
  }

  window.drawBorderOnTop = drawBorderOnTop;
  canvas.off("after:render");
  canvas.on("after:render", drawBorderOnTop);
  canvas.requestRenderAll();

  updatePositionInfo();
}

function removeBorderFromTop() {
  const ctx = canvas.contextTop;
  if (!ctx) return;

  canvas.clearContext(ctx);

  canvas.requestRenderAll();
}
window.removeBorderFromTop = removeBorderFromTop;

function fitImageToFrame(cover = false) {
  if (!appState.uploadedImage) return;

  const W = appState.uploadedImage.width;
  const H = appState.uploadedImage.height;

  const scaleX = appState.selectedWidth / W;
  const scaleY = appState.selectedHeight / H;

  let newScale = cover ? Math.max(scaleX, scaleY) : Math.min(scaleX, scaleY);
  if (!isFinite(newScale) || newScale <= 0) newScale = 1;

  appState.uploadedImage.scaleX = newScale;
  appState.uploadedImage.scaleY = newScale;
  appState.scaleFactor = newScale;

  centerImage();
  appState.uploadedImage.setCoords();
  updatePositionInfo();
  applyDpiLimitAndSync(true);
  canvas.requestRenderAll();
}

function coverFrame() {

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
    applyDpiLimitAndSync(true);
    drawBorderOnTop();
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
    applyDpiLimitAndSync(true);
    drawBorderOnTop();
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
  updatePositionInfo();
}

// --- Event Handlers ---
// document.getElementById("zoom-in").addEventListener("click", () => {
//   if (appState.uploadedImage) {
//     appState.scaleFactor *= 1.1;
//     appState.uploadedImage.scaleX = appState.scaleFactor;
//     appState.uploadedImage.scaleY = appState.scaleFactor;
//     appState.uploadedImage.setCoords();
//     centerImage();
//     updatePositionInfo();
//   }
// });

// document.getElementById("zoom-out").addEventListener("click", () => {
//   if (appState.uploadedImage) {
//     appState.scaleFactor *= 0.9;
//     appState.uploadedImage.scaleX = appState.scaleFactor;
//     appState.uploadedImage.scaleY = appState.scaleFactor;
//     appState.uploadedImage.setCoords();
//     centerImage();
//     updatePositionInfo();
//   }
// });

// document.getElementById("fit-to-frame").addEventListener("click", () => {
//   fitImageToFrame(false);
//   updatePositionInfo();
// });

document.getElementById("center-image").addEventListener("click", () => {
  centerImage();
  applyDpiLimitAndSync(true);
});

document.getElementById("fill-front-image").addEventListener("click", () => {
   coverFrame();
  applyDpiLimitAndSync(true);
});
// document.getElementById("fill-side-image").addEventListener("click", () => {
//  fitImageToFrame(true);
//  updatePositionInfo();
// });
document.getElementById("fit-front-image").addEventListener("click", () => {
   FitFrontFrame();
  applyDpiLimitAndSync(true);
});

document.getElementById("frameColorOptions").addEventListener("change", function (e) {
  if (e.target.name === "frameColor") {
    const color = e.target.getAttribute("data-color") || "#000000";

    // ✅ store color globally
    appState.frameColor = color;

    // Update fabric outer frame
    if (appState.outerFrame) {
      appState.outerFrame.set("fill", color);
      canvas.requestRenderAll();
    }

    this.setAttribute("data-current-color", color);

    // ✅ redraw top border with new color
    drawBorderOnTop();
  }

  updatePositionInfo();
});

function updateFrameSize(selectedOption) {
  const resolvedSizeOption =
    (selectedOption && selectedOption.name === "frameSize")
      ? selectedOption
      : document.querySelector('#frameSizeOptions [name="frameSize"]:checked');
  if (!resolvedSizeOption) return;

  const selectedRadio = document.querySelector('input[name="orientation"]:checked');
    const selectedOrientation = selectedRadio ? selectedRadio.value : "portrait";
   const selectedsize = document.querySelector('input[name="frameSize"]:checked');
    const originalsize = resolvedSizeOption.getAttribute("data-original-size");
    const [width1, height1] = originalsize.split("x").map(Number);

    document.querySelectorAll(".selected-size").forEach(el => {
      el.textContent = selectedsize.value;
    });

    let dataratio;
 let size;
  if (window.innerWidth < 680) {
    size = resolvedSizeOption.getAttribute("data-pixel-mobile");
    dataratio = resolvedSizeOption.getAttribute("data-ratio-mobile");
  } else {
    size = resolvedSizeOption.getAttribute("data-pixel-desktop");
    dataratio = resolvedSizeOption.getAttribute("data-ratio-desktop");
  }
//const size = selectedOption.getAttribute("data-size");
  const frmsize = resolvedSizeOption.getAttribute("data-frmsize");
  const [width, height] = size.split("x").map(Number);
  const [frmwidth, frmheight] = frmsize.replace(/″/g, '').split('×').map(s => Number(s.trim()));
  


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
       const bordersizeElement = document.getElementById("brd-size");
    const borderColorElement = document.getElementById("brd-color");

    
    if (orgWElement) orgWElement.textContent = appState.originalWidth;
    if (orgHElement) orgHElement.textContent = appState.originalHeight;
    if (frnWElement) frnWElement.textContent = appState.selectedWidth;
    if (frmHElement) frmHElement.textContent = appState.selectedHeight;
    if (ratioElement) ratioElement.textContent = dataratio;
    if (cvswElement) cvswElement.textContent = appState.originalWidth;
    if (cvshElement) cvshElement.textContent = appState.originalHeight;
    if (bordersizeElement) bordersizeElement.textContent = appState.borderSize ;
  if (borderColorElement) borderColorElement.textContent = appState.frameColor;

    
    // Handle canvas updates
    canvas.setWidth(appState.selectedWidth);
    canvas.setHeight(appState.selectedHeight);
    
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
         coverFrame();
    }
    

  updatePositionInfo();
  applyDpiLimitAndSync(true);

  // Update DPI display
  updateDPIDisplay();
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

// Helper function for DPI display (extracted from main function)
function updateDPIDisplay() {

  // const dpiElement = document.querySelector(".dpi-num");
  // const iconElement = document.querySelector(".dpi-state-icon");
  const boostBtn = document.querySelector(".boost-img-btn");
  const confirmBtn = document.querySelector(".image-conform-btn");

  const currentDpi = Number((appState.dpi || 0).toFixed(2));

  if (!boostBtn) return;

  if (currentDpi > 0 && currentDpi < 30) {
  // dpiElement.textContent = `Needs Upscale`;
  //   dpiElement.style.color = "red";

  //    iconElement.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
  //     <path d="M9.9891 0C4.49317 0 0 4.49317 0 9.9891C0 15.4859 4.49317 20 9.9891 20C15.485 20 20 15.5068 20 9.9891C20 4.47115 15.5068 0 9.9891 0ZM9.9891 18.3208C5.40912 18.3208 1.67946 14.5911 1.67946 10.0111C1.67946 5.43115 5.40912 1.70148 9.9891 1.70148C14.5691 1.70148 18.2987 5.43115 18.2987 10.0111C18.3207 14.5911 14.5909 18.3208 9.9891 18.3208Z" fill="#FF0606"/>
  //     <path d="M10.1207 4.56252C9.74952 4.56252 9.44421 4.69326 9.20466 4.93365C8.98621 5.1732 8.85547 5.52239 8.85547 5.93651C8.85547 6.24185 8.8774 6.72177 8.92126 7.41931L9.16081 10.9307C9.20466 11.4106 9.29154 11.7379 9.37926 11.9774C9.48806 12.2389 9.70651 12.3696 10.0118 12.3696C10.3172 12.3696 10.5137 12.2389 10.6444 11.9774C10.7532 11.7379 10.841 11.3887 10.8629 10.9526L11.1682 7.33156C11.2121 7.0043 11.2121 6.65511 11.2121 6.34977C11.2121 5.78297 11.1463 5.34691 10.9936 5.04073C10.884 4.7371 10.5787 4.56252 10.1207 4.56252Z" fill="#FF0606"/>
  //     <path d="M10.0549 13.4844C9.72761 13.4844 9.44421 13.5932 9.20466 13.8336C8.96511 14.0731 8.85547 14.3354 8.85547 14.6627C8.85547 15.0338 8.9862 15.3391 9.2266 15.5348C9.46615 15.7313 9.75039 15.8402 10.0768 15.8402C10.3821 15.8402 10.6655 15.7313 10.9059 15.5129C11.1455 15.2944 11.277 14.6408 11.277 14.6408C11.277 14.3135 11.1682 14.0301 10.9278 13.7906C10.6655 13.5932 10.3813 13.4844 10.0549 13.4844Z" fill="#FF0606"/>
  //   </svg>`;

    boostBtn.style.display = "flex";
    boostBtn.classList.add("show");

  } else if (currentDpi >= 30) {
//    dpiElement.textContent = `Good To Print`;
//     dpiElement.style.color = "green";

//     iconElement.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
// <path d="M10 0C4.48421 0 0 4.48421 0 10C0 15.5158 4.48421 20 10 20C15.5158 20 20 15.5158 20 10C20 4.48421 15.5158 0 10 0ZM10 17.8105C5.68421 17.8105 2.18947 14.2947 2.18947 10C2.18947 5.70526 5.68421 2.18947 10 2.18947C14.3158 2.18947 17.8105 5.68421 17.8105 10C17.8105 14.3158 14.3158 17.8105 10 17.8105Z" fill="#1B8600"/>
// <path d="M12.7139 6.92258L8.90337 10.7542L7.28232 9.13311C6.86127 8.71205 6.16653 8.71205 5.74548 9.13311C5.32442 9.55416 5.32442 10.2489 5.74548 10.6699L8.14548 13.0699C8.356 13.2805 8.62969 13.3857 8.92443 13.3857C9.21916 13.3857 9.49285 13.2805 9.70337 13.0699L14.2928 8.48047C14.7139 8.05942 14.7139 7.36469 14.2928 6.94363C13.8507 6.50153 13.156 6.50153 12.7139 6.92258Z" fill="#1B8600"/>
// </svg>`;

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

  schedule3DPreviewUpdate();
}

document.getElementById("frameSizeOptions").addEventListener("change", function(e) {
  if (e.target.name === "frameSize") {
    updateFrameSize(e.target);
  }
});
document.getElementById("frameOrientationOptions").addEventListener("change", function(e) {
  if (e.target.name === "orientation") {
    updateFrameSize(e.target);
  }
});


window.addEventListener("load", () => {
  const selectedOption = document.querySelector('#frameSizeOptions [name="frameSize"]:checked');
  if (selectedOption) {
    updateFrameSize(selectedOption);
  }
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
        strokeWidth: 1,
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

canvas.on('object:added', function(e) {
  if (e.target.name === 'centerLine') {
    canvas.moveTo(e.target, 9999);
  }
});

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

uploadInput.addEventListener("change", function(e) {
  (async () => {
    let file = e.target.files[0];
    if (!file) return;

    const allowedTypes = [
    "image/jpeg",
    "image/png",
    "image/heic",
    "image/heif"
  ];

    const isHeic = pdpV4IsHeicFile(file);
    const fileType = (file.type || "").toLowerCase();
    const isAllowed = allowedTypes.includes(fileType) || isHeic;

    if (!isAllowed) {
      alert("Only JPEG, PNG, or HEIC/HEIF images are allowed.");
      uploadInput.value = "";
      return;
    }

    let fileForUse = file;
    let previewUrl = null;
    let dataUrlOverride = null;

    if (isHeic) {
      try {
        const converted = await pdpV4ConvertHeicToJpeg(file);
        fileForUse = converted.file;
        previewUrl = converted.blobUrl;
        dataUrlOverride = converted.dataUrl;
      } catch (err) {
        console.error("HEIC conversion failed:", err);
        alert("Failed to convert HEIC image. Please try a JPEG or PNG file instead.");
        uploadInput.value = "";
        return;
      }
    } else {
      previewUrl = URL.createObjectURL(fileForUse);
    }

  appState.uploadimgsize = +(fileForUse.size / (1024 * 1024)).toFixed(2);
  // 🔹 Send image to API (use converted file if HEIC)
  uploadImageToAPI(fileForUse);

  const img = new Image();
  img.onload = function() {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    galleryWrapper.style.display = "none";
    uploadInputwrap.style.display = "none";
    customForm.style.display = "block";

    const handleDataUrl = (dataUrl) => {
      const mainImgWrap = document.querySelector(".main-img-wrap");
      if (mainImgWrap) {
        mainImgWrap.setAttribute("data-main-img", dataUrl);
      }

      fabric.Image.fromURL(dataUrl, function(fabricImg) {
        appState.uploadedImage = fabricImg;
        const imgfileWElement = document.getElementById("img-file-w");
        const imgfileHElement = document.getElementById("img-file-h");

        if (imgfileWElement) imgfileWElement.textContent = fabricImg.width;
        if (imgfileHElement) imgfileHElement.textContent = fabricImg.height;

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

        appState.uploadedImage.setControlsVisibility({
          mt: false,
          mb: false,
          ml: false,
          mr: false,
          mtr: false,
        });

        canvas.add(appState.uploadedImage);
        applyFrameClip();
        setMovementConstraints(); 
        canvas.setActiveObject(appState.uploadedImage);
        canvas.moveTo(appState.uploadedImage, 2);

          coverFrame();


        canvas.renderAll();
         syncZoomSlider();
        
      });
    };

    if (dataUrlOverride) {
      handleDataUrl(dataUrlOverride);
    } else {
      const reader = new FileReader();
      reader.onload = function(f) {
        handleDataUrl(f.target.result);
      };
      reader.onerror = function(err) {
        console.error("Failed to read image:", err);
        alert("Failed to load image. Please try another file.");
        uploadInput.value = "";
      };
      reader.readAsDataURL(fileForUse);
    }
     document.querySelectorAll(".image-conform-btn").forEach(div => {
  div.style.pointerEvents = "auto";
  div.style.opacity = "1";
});
  };
  img.onerror = function() {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    alert("Could not load this image in your browser. Please try a JPEG or PNG file.");
    uploadInput.value = "";
  };

  img.src = previewUrl;
  })();
});


const slider = document.getElementById("zoomSlider");
const zoomInBtn = document.getElementById("zoomIn");
const zoomOutBtn = document.getElementById("zoomOut");
const zoomLabel = document.getElementById("zoomLabel");

const canvasW = document.getElementById("frm-w")?.textContent || 1;
const canvasH = document.getElementById("frm-h")?.textContent || 1;

let imgWidthInches = 6;
let imgHeightInches = 4;
let scale = 1;
const MIN_PRINT_DPI = 30;
let zoomLimitToastTimer = null;
let zoomLimitToastEl = null;

function updateSliderBackground(slider) {
  if (!slider) return;
  
  const value = ((slider.value - slider.min) / (slider.max - slider.min)) * 100;
  
  const currentDpi = Number((appState.dpi || 0).toFixed(2));
  
  let backgroundColor;
  if (currentDpi < 30) {
    backgroundColor = `linear-gradient(to right, #1F8FE5 ${value}%, #ff4444 ${value}%)`;
    slider.classList.add('dpi-warning-slider');
  } else {
    backgroundColor = `linear-gradient(to right, #1F8FE5 ${value}%, rgb(255, 255, 255) ${value}%)`;
    slider.classList.remove('dpi-warning-slider');
  }
  
  slider.style.background = backgroundColor;
}

function getCurrentImageZoom() {
  if (!appState.uploadedImage) return appState.zoom || 1;

  const baseScale = getBaseScale();
  if (baseScale <= 0 || !isFinite(baseScale)) return appState.zoom || 1;

  const currentZoom = appState.uploadedImage.scaleX / baseScale;
  if (!isFinite(currentZoom) || currentZoom <= 0) return appState.zoom || 1;

  return currentZoom;
}

function getMaxZoomForMinDpi(minDpi = MIN_PRINT_DPI) {
  const currentDpi = Number(appState.dpi || 0);
  const currentZoom = getCurrentImageZoom();

  if (!isFinite(currentDpi) || currentDpi <= 0 || !isFinite(currentZoom) || currentZoom <= 0) {
    return appState.maxZoom;
  }

  const targetZoom = currentZoom * (currentDpi / minDpi);
  if (!isFinite(targetZoom) || targetZoom <= 0) return appState.maxZoom;

  return Math.max(appState.minZoom, Math.min(appState.maxZoom, targetZoom));
}

function getDynamicMaxZoom() {
  return getMaxZoomForMinDpi(MIN_PRINT_DPI);
}

function clampZoomByDpi(newZoom, minDpi = MIN_PRINT_DPI) {
  const boundedZoom = Math.max(appState.minZoom, Math.min(appState.maxZoom, newZoom));
  const dpiLimitedMaxZoom = getMaxZoomForMinDpi(minDpi);
  return Math.max(appState.minZoom, Math.min(boundedZoom, dpiLimitedMaxZoom));
}

function isAtDynamicMaxZoom(epsilon = 0.01) {
  const currentZoom = getCurrentImageZoom();
  const dynamicMax = getDynamicMaxZoom();
  return currentZoom >= (dynamicMax - epsilon);
}

function getZoomLimitToastElement() {
  if (zoomLimitToastEl) return zoomLimitToastEl;

  const el = document.createElement("div");
  el.id = "zoom-limit-toast";
  el.style.cssText = `
       position: fixed;
    left: 50%;
    bottom: 130px;
    transform: translateX(-50%);
    background: rgba(20, 20, 20, 1);
    color: #fff;
    font-size: 12px;
    padding: 8px 12px;
    border-radius: 8px;
    z-index: 9999;
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.2s ease;
    border: 1px solid rgba(255, 255, 255, 0.15);
    white-space: nowrap;
  `;
  el.textContent = "You reach max zoom image resolution";
  document.body.appendChild(el);
  zoomLimitToastEl = el;
  return el;
}

function showZoomLimitMessage() {
  const toast = getZoomLimitToastElement();
  toast.style.opacity = "1";

  if (zoomLimitToastTimer) {
    clearTimeout(zoomLimitToastTimer);
  }

  zoomLimitToastTimer = setTimeout(() => {
    toast.style.opacity = "0";
    zoomLimitToastTimer = null;
  }, 1200);
}

function applyDpiLimitAndSync(showMessageOnLimit = true) {
  const wasAtLimitBefore = isAtDynamicMaxZoom();
  const wasCapped = enforceMinimumDpi(MIN_PRINT_DPI);
  syncZoomSlider();
  updateZoomControlsState();
  const isAtLimitAfter = isAtDynamicMaxZoom();
  if (showMessageOnLimit && (wasCapped || wasAtLimitBefore || isAtLimitAfter)) {
    showZoomLimitMessage();
  }
  return wasCapped;
}

function updateZoomControlsState() {
  const slider = document.getElementById("zoomSlider");
  const zoomInBtn = document.getElementById("zoomIn");
  const dynamicMaxZoom = getDynamicMaxZoom();

  if (slider) {
    slider.min = String(appState.minZoom * 100);
    slider.max = String(Math.round(dynamicMaxZoom * 100));
    slider.value = String(Math.round(getCurrentImageZoom() * 100));
    updateSliderBackground(slider);
  }

  if (zoomInBtn) {
    if (isAtDynamicMaxZoom()) {
      zoomInBtn.style.opacity = "0.5";
      zoomInBtn.style.cursor = "not-allowed";
    } else {
      zoomInBtn.style.opacity = "1";
      zoomInBtn.style.cursor = "pointer";
    }
  }
}

function enforceMinimumDpi(minDpi = MIN_PRINT_DPI) {
  if (!appState.uploadedImage) return false;

  const currentZoom = getCurrentImageZoom();
  const targetZoom = clampZoomByDpi(currentZoom, minDpi);

  if (!isFinite(targetZoom) || targetZoom <= 0) return false;
  if (targetZoom >= (currentZoom - 0.000001)) return false;

  updateZoom(targetZoom);
  updatePositionInfo();
  syncZoomSlider();
  updateZoomControlsState();
  return true;
}

function isZoomAllowed(newZoom) {
  const requested = Math.max(appState.minZoom, Math.min(appState.maxZoom, newZoom));
  const allowed = clampZoomByDpi(requested, MIN_PRINT_DPI);
  return allowed >= (requested - 0.000001);
}

function initZoomSlider() {
  const slider = document.getElementById("zoomSlider");
  if (!slider) return;
  slider.min = String(appState.minZoom * 100);
  slider.max = String(Math.round(getDynamicMaxZoom() * 100));
  slider.value = String(appState.zoom * 100);
  updateSliderBackground(slider);
  syncZoomSlider();
}


document.addEventListener("DOMContentLoaded", function() {
  initZoomSlider();
  const slider = document.getElementById("zoomSlider");
  if (slider && slider.dataset.zoomBound !== "1") {
    slider.addEventListener("input", function() {
      handleZoomSlider(this);
    });
    slider.dataset.zoomBound = "1";
  }
  
  // zoom button click handlers are bound once below.
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
    const requestedZoom = Math.max(appState.minZoom, Math.min(appState.maxZoom, newZoom));
    const dpiMaxZoom = getDynamicMaxZoom();
    newZoom = clampZoomByDpi(requestedZoom, MIN_PRINT_DPI);
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
    updateZoomControlsState();
    canvas.requestRenderAll();
    return {
      requestedZoom,
      appliedZoom: newZoom,
      dpiMaxZoom,
      hitLimit: requestedZoom > (newZoom + 0.000001)
    };
  } catch (error) {
    console.error("Error in updateZoom:", error);
    return {
      requestedZoom: newZoom,
      appliedZoom: appState.zoom,
      dpiMaxZoom: getDynamicMaxZoom(),
      hitLimit: false
    };
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
      Math.min(getDynamicMaxZoom(), currentZoom)
    );
    
    // Update slider
    slider.min = String(appState.minZoom * 100);
    slider.max = String(Math.round(getDynamicMaxZoom() * 100));
    slider.value = String(Math.round(appState.zoom * 100));
    
    updateSliderBackground(slider);
    updateZoomLabel();
    updateZoomControlsState();
  } catch (error) {
    console.error("Error in syncZoomSlider:", error);
  }
}

 function handleZoomSlider(slider) {
  if (!appState.uploadedImage) return;
  
  try {
    const zoomValue = parseFloat(slider.value) / 100;
    const result = updateZoom(zoomValue);
    if (result && result.hitLimit) {
      showZoomLimitMessage();
    }
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



document.addEventListener("DOMContentLoaded", function() {
  const edgesCheckbox = document.getElementById("enable-edges");
  if (edgesCheckbox) {
    edgesCheckbox.addEventListener("change", function() {
      if (appState.uploadedImage) {
        handleZoomSlider(document.getElementById("zoomSlider"));
      }
    });
  }
});

function zoomIn() {
  if (!appState.uploadedImage) return;
  if (isAtDynamicMaxZoom()) {
    showZoomLimitMessage();
    updateZoomControlsState();
    return;
  }
  
  const newZoom = appState.zoom * 1.1;
  const result = updateZoom(newZoom);
  if ((result && result.hitLimit) || isAtDynamicMaxZoom()) {
    showZoomLimitMessage();
  }
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

if (zoomInBtn) {
  zoomInBtn.addEventListener("click", zoomIn);
}
if (zoomOutBtn) {
  zoomOutBtn.addEventListener("click", zoomOut);
}
if (slider && slider.dataset.zoomBound !== "1") {
  handleZoomSlider(slider);
  slider.addEventListener("input", () => handleZoomSlider(slider));
  slider.dataset.zoomBound = "1";
}

// document.getElementById("zoomIn").addEventListener("click", () => {
//   if (appState.uploadedImage) {
//     appState.scaleFactor *= 1.1;
//     appState.uploadedImage.scaleX = appState.scaleFactor;
//     appState.uploadedImage.scaleY = appState.scaleFactor;
//     appState.uploadedImage.setCoords();
//     updateMovementConstraints();
//     centerImage();
//     syncZoomSlider()
//     updatePositionInfo();
//   }
// });

// document.getElementById("zoomOut").addEventListener("click", () => {
//   if (appState.uploadedImage) {
//     appState.scaleFactor *= 0.9;
//     appState.uploadedImage.scaleX = appState.scaleFactor;
//     appState.uploadedImage.scaleY = appState.scaleFactor;
//     appState.uploadedImage.setCoords();
//     updateMovementConstraints();
//     centerImage();
//     syncZoomSlider()
//     updatePositionInfo();
//   }
// });

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
      '40″×55″',
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
        appState.uploadedImage = img;
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

           FitFrontFrame();
           applyFrameClip();
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

document.addEventListener("DOMContentLoaded", function() {

  function updateVariantId() {

    const size = document.querySelector("input[name=\"frameSize\"]:checked")?.value;
    const color = document.querySelector("input[name=\"frameColor\"]:checked")?.value;

    if (!size || !color) return;

    const variant = window.productVariants.find(
      (v) => v.option2 === size && v.option1 === color,
    );

    if (variant) {
      
      const variantInput = document.querySelector("input[name=\"id\"]");
      if (variantInput) variantInput.value = variant.id;

      const variantInputColor = document.querySelector("input[name=\"properties[_pdp-color]\"]");
      if (variantInputColor) variantInputColor.value = variant.option1;

      const variantInputSize = document.querySelector("input[name=\"properties[_pdp-size]\"]");
      if (variantInputSize) variantInputSize.value = variant.option2;

      const variantInputId = document.querySelector("input[name=\"properties[_pdp-variant-id]\"]");
      if (variantInputId) variantInputId.value = variant.sku;

      let numericPrice = null;
      let numericCmpPrice = null;

    // Base price
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
      logAllAddedElements();
      const productImage = document.querySelector(".image-magnify-lightbox");
      if (productImage && variant.image) {
        const imageUrl = typeof variant.image === "string" ? variant.image : variant.image.src;

        productImage.src = imageUrl;

        const widths = [246, 493, 600, 713, 823, 990, 1100, 1206, 1346, 1426, 1646, 1946];
        productImage.srcset = widths.map(w => `${imageUrl}?width=${w} ${w}w`).join(", ");
        productImage.alt = variant.image.alt || `${variant.option1} / ${variant.option2}`;
      }
    }
  }

  document.querySelectorAll("input[name=\"frameSize\"], input[name=\"frameColor\"]").forEach((input) => {
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
  const finalpopup = document.querySelector(".finalize-image-popup");
  const finalpopup1 = document.querySelector("#is-first");
  const finalpopup2 = document.querySelector("#is-second");

  if (finalpopup) finalpopup.style.display = "none";
  if (finalpopup1) finalpopup1.style.display = "none";
  if (finalpopup2) finalpopup2.style.display = "none";

  const btn = e.currentTarget;
  const originalText = btn.textContent;
  btn.textContent = "Adding...";
  btn.disabled = true;

  try {
    const mainImgWrap = document.querySelector(".main-img-wrap");
    if (!mainImgWrap) throw new Error("No .main-img-wrap element found");

    const imageData = mainImgWrap.getAttribute("data-main-img");
    if (!imageData) throw new Error("No image data found in data-main-img");

    const base64ToBlob = (base64) => {
      const [meta, data] = base64.split(",");
      const mime = meta.match(/:(.*?);/)[1];

      const byteString = atob(data);
      const ab = new ArrayBuffer(byteString.length);
      const ia = new Uint8Array(ab);

      for (let i = 0; i < byteString.length; i++) {
        ia[i] = byteString.charCodeAt(i);
      }

      return new Blob([ab], { type: mime });
    };

    const formData = new FormData();
    const userId = window.shopifyCustomerId || "guest";
    const sessionId = getLocalStorage1Day("sessionId") || "none";

    if (imageData.startsWith("http") || imageData.startsWith("//")) {
      formData.append("imageUrl", imageData);
    } 
    else if (imageData.startsWith("data:image/")) {
      formData.append(
        "file",
        base64ToBlob(imageData),
        "uploaded-image.jpeg"
      );
    } 
    else {
      throw new Error("Invalid image data format");
    }

    formData.append("customerId", userId);
    formData.append("sessionId", sessionId);

    const response = await fetch(
      `${window.Prompt2Prints.apiBase}/upload-image`,
      {
        method: "POST",
        headers: {
          "x-api-key": window.Prompt2Prints.apiKey
        },
        body: formData,
      }
    );

    if (!response.ok) {
      throw new Error("Image upload API failed");
    }

    const data = await response.json();

    const imageUpscale = document.querySelector('input[name="properties[_pdp-allow-upscale]"]');
    const imageUpscaletag = document.querySelector('input[name="properties[_pdp-img-tag]"]');

    if (!imageUpscale || !imageUpscaletag) {
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

    imageUpscale.setAttribute("value", imageUpscale.value);
    imageUpscaletag.setAttribute("value", imageUpscaletag.value);

    const hiddenInput = document.getElementById("final-image-data");
    if (hiddenInput && data.cloudfrontLink) {
      hiddenInput.value = data.cloudfrontLink;
    }

    const frmcolor = appState.frameColor;
    await exportFullDivAsImage(userId, sessionId, frmcolor);

    btn.textContent = "Added!";
    
    const customForm = document.getElementById('custom-image-form');
    customForm.submit();

  } catch (error) {
    console.error("sendMainImageToAPI error:", error);
    btn.textContent = "Failed. Try again";
  } finally {
    btn.disabled = false;
    setTimeout(() => {
      btn.textContent = originalText;
    }, 2000);
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
      // Calculate innerPadding first
      let innerPadding;
      const size = `${appState.selectedWidth}x${appState.selectedHeight}`;
      
      if (window.innerWidth < 680) {
        if (size === "1056x1248") {
          innerPadding = 144 / 6.24;
        } else if (size === "1152x1440") {
          innerPadding = 144 / 7.2;
        } else if (size === "1344x1632") {
          innerPadding = 144 / 8.16;
        } else if (size === "1440x1440") {
          innerPadding = 144 / 7.2;
        } else if (size === "1440x1824") {
          innerPadding = 144 / 9.12;
        } else if (size === "1440x2016") {
          innerPadding = 144 / 10.08;
        } else if (size === "1824x1824") {
          innerPadding = 144 / 9.12;
        } else if (size === "1824x2208") {
          innerPadding = 144 / 11.04;
        } else if (size === "2016x2592") {
          innerPadding = 144 / 12.96;
        } else if (size === "2208x2976") {
          innerPadding = 144 / 14.88;
        } else if (size === "2208x3168") {
          innerPadding = 144 / 15.84;
        } else if (size === "2592x3360") {
          innerPadding = 144 / 16.8;
        } else if (size === "2592x3744") {
          innerPadding = 144 / 18.72;
        } else {
          innerPadding = null;
        }
      } else {
        if (size === "1056x1248") {
          innerPadding = 144 / 3.12;
        } else if (size === "1152x1440") {
          innerPadding = 144 / 3.6;
        } else if (size === "1344x1632") {
          innerPadding = 144 / 4.08;
        } else if (size === "1440x1440") {
          innerPadding = 144 / 3.6;
        } else if (size === "1440x1824") {
          innerPadding = 144 / 4.56;
        } else if (size === "1440x2016") {
          innerPadding = 144 / 5.04;
        } else if (size === "1824x1824") {
          innerPadding = 144 / 4.56;
        } else if (size === "1824x2208") {
          innerPadding = 144 / 5.52;
        } else if (size === "2016x2592") {
          innerPadding = 144 / 6.48;
        } else if (size === "2208x2976") {
          innerPadding = 144 / 7.44;
        } else if (size === "2208x3168") {
          innerPadding = 144 / 7.92;
        } else if (size === "2592x3360") {
          innerPadding = 144 / 8.4;
        } else if (size === "2592x3744") {
          innerPadding = 144 / 9.36;
        } else {
          innerPadding = null;
        }
      }

      // Create a clipping rectangle to cut innerPadding from the image
      const clipRect = new fabric.Rect({
        left: innerPadding / 2,
        top: innerPadding / 2,
        width: appState.selectedWidth - innerPadding,
        height: appState.selectedHeight - innerPadding,
        absolutePositioned: true
      });

      // Apply the clipping mask to the image
      newImg.clipPath = clipRect;

      // Set position and other properties
      newImg.set({ 
        left, 
        top, 
        scaleX, 
        scaleY, 
        angle, 
        originX, 
        originY 
      });

      // Remove old image and add new one
      canvas.remove(img);
      canvas.add(newImg);
      window.addedElements.push(newImg);

      // Add border (if still needed for visual reference)
      const borderSize = innerPadding;
      const border = new fabric.Rect({
        top: 0,
        left: 0,
        width: appState.selectedWidth - borderSize,
        height: appState.selectedHeight - borderSize,
        fill: 'transparent',
        stroke: 'rgb(0, 0, 0)',
        strokeWidth: borderSize,
        selectable: false,
        evented: false
      });

      canvas.add(border);
      canvas.bringToFront(border);
      window.addedElements.push(border);

      resolve(newImg);
      logAllAddedElements();
    }, {
      crossOrigin: "anonymous"
    });
  });
}

// async function exportFullDivAsImage(customerId, sessionId, frmcolor) {
//   const parentDiv = document.querySelector(".back-image");
//   if (!parentDiv) {
//     console.error("No element with class .back-image found");
//     return;
//   }

//   if (typeof canvas === "undefined") {
//     console.error("Fabric.js canvas not defined");
//     return;
//   }

//   canvas.discardActiveObject();
//   canvas.getObjects().forEach(obj => obj.set({
//     selectable: false,
//     evented: false
//   }));
// const originalBgColor = canvas.backgroundColor || null;

//   canvas.setBackgroundColor("#ffffff", canvas.renderAll.bind(canvas));

//   canvas.renderAll();

//   try {
//     const images = canvas.getObjects("image");
//     await Promise.all(images.map(img => reloadImageAsBase64(img)));
    

//     // 1️⃣ Export canvas to data URL
//     const dataURL = canvas.toDataURL({
//       format: "jpeg",
//       multiplier: 2,
//     });
//    const frnheight = appState.originalHeight;
//   const frmwidth = appState.originalWidth;
//   let size = `${frmwidth}x${frnheight}`;

//   const sortedSize = [frmwidth, frnheight].sort((a, b) => a - b).join("x");

//   let innerPadding;

//   let paddingMap = {}; 
//    if (window.innerWidth < 680) {
//      paddingMap = {
//         "1056x1248" : 144 / 6.24,
//     "1152x1440" : 144 / 7.2,
//     "1344x1632" : 144 / 8.16,
//     "1440x1440" : 144 / 7.2,
//     "1440x1824" : 144 / 9.12,
//     "1440x2016" : 144 / 10.08,
//     "1824x1824" : 144 / 9.12,
//     "1824x2208" : 144 / 11.04,
//     "2016x2592" : 144 / 12.96,
//     "2208x2976" : 144 / 14.88,
//     "2208x3168" : 144 / 15.84,
//     "2592x3360" : 144 / 16.8,
//     "2592x3744" : 144 / 18.72,
//      }

// } else {
//     paddingMap = {
//         "1056x1248" : 144 / 3.12,
//     "1152x1440" : 144 / 3.6,
//     "1344x1632" : 144 / 4.08,
//     "1440x1440" : 144 / 3.6,
//     "1440x1824" : 144 / 4.56,
//     "1440x2016" : 144 / 5.04,
//     "1824x1824" : 144 / 4.56,
//     "1824x2208" : 144 / 5.52,
//     "2016x2592" : 144 / 6.48,
//     "2208x2976" : 144 / 7.44,
//     "2208x3168" : 144 / 7.92,
//     "2592x3360" : 144 / 8.4,
//     "2592x3744" : 144 / 9.36,
//      }

// }

// function getPadding(size) {
//   // normalize
//   const [w, h] = size.split("x").map(Number);
//   const key = `${Math.min(w,h)}x${Math.max(w,h)}`; // always smaller first
//   return paddingMap[key] ?? null;
// }
// innerPadding = getPadding(size);
// const frmbordercolor = frmcolor;
//     const paddedDataURL = await addPaddingToDataURL(dataURL, innerPadding, frmbordercolor);

//     const res = await fetch(paddedDataURL);
//     const blob = await res.blob();

//     const formData = new FormData();
//      if (blob) {
//   formData.append("file", blob, "full-div-image.jpeg");
// } else if (cloudfrontLink) {
//   formData.append("imageUrl", cloudfrontLink);
// }
//     formData.append("customerId", customerId);
//     formData.append("sessionId", sessionId);
//     formData.append("thumbnailWidth", "200");

//     const response = await fetch(`${window.Prompt2Prints.apiBase}/image-thumbnail`, {
//       method: "POST",
//       body: formData,
//     });

//     const data = await response.json();

//     const hiddenInput = document.getElementById("preview-image-data");
//     if (hiddenInput && data.original?.cloudfrontUrl) hiddenInput.value = data.original.cloudfrontUrl;

//     const hiddenInput1 = document.getElementById("preview-thumb-image-data");
//     if (hiddenInput1 && data.thumbnail?.cloudfrontUrl) hiddenInput1.value = data.thumbnail.cloudfrontUrl;

//     // Optional: display padded image in .full-content
//     let fullContentDiv = document.querySelector(".full-content");
//     if (!fullContentDiv) {
//       fullContentDiv = document.createElement("div");
//       fullContentDiv.className = "full-content";
//       document.body.appendChild(fullContentDiv);
//     }
//     fullContentDiv.innerHTML = "";
//     const imgElement = document.createElement("img");
//     imgElement.src = paddedDataURL;
//     fullContentDiv.appendChild(imgElement);
//     removeSelectedElements([1, 2, 3]);

//   } catch (err) {
//     console.error("Error exporting full div:", err);
//   } finally {
//     canvas.getObjects().forEach(obj => obj.set({
//       selectable: true,
//       evented: true
//     }));
//       canvas.setBackgroundColor(originalBgColor, canvas.renderAll.bind(canvas));
//     canvas.renderAll();
//   }
// }
// function addPaddingToDataURL(dataURL, padding = 50, bgColor) {
//   return new Promise((resolve) => {
//     const img = new Image();
//     img.src = dataURL;
//     img.onload = () => {
//       const canvas = document.createElement("canvas");
//       canvas.width = img.width + padding * 2;
//       canvas.height = img.height + padding * 2;
//       const ctx = canvas.getContext("2d");
//       ctx.fillStyle = bgColor;
//       ctx.fillRect(0, 0, canvas.width, canvas.height);
//       ctx.drawImage(img, padding, padding);

//       resolve(canvas.toDataURL("image/jpeg"));
//     };
//   });
// }

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
        if (obj.stroke === 'red' && obj.opacity === 0.5) {
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
        if (size === "1056x1248") innerPadding = 144 / 6.24;
        else if (size === "1152x1440") innerPadding = 144 / 7.2;
        else if (size === "1344x1632") innerPadding = 144 / 8.16;
        else if (size === "1440x1440") innerPadding = 144 / 7.2;
        else if (size === "1440x1824") innerPadding = 144 / 9.12;
        else if (size === "1440x2016") innerPadding = 144 / 10.08;
        else if (size === "1824x1824") innerPadding = 144 / 9.12;
        else if (size === "1824x2208") innerPadding = 144 / 11.04;
        else if (size === "2016x2592") innerPadding = 144 / 12.96;
        else if (size === "2208x2976") innerPadding = 144 / 14.88;
        else if (size === "2208x3168") innerPadding = 144 / 15.84;
        else if (size === "2592x3360") innerPadding = 144 / 16.8;
        else if (size === "2592x3744") innerPadding = 144 / 18.72;
        else innerPadding = null;
      } else {
        if (size === "1056x1248") innerPadding = 144 / 3.12;
        else if (size === "1152x1440") innerPadding = 144 / 3.6;
        else if (size === "1344x1632") innerPadding = 144 / 4.08;
        else if (size === "1440x1440") innerPadding = 144 / 3.6;
        else if (size === "1440x1824") innerPadding = 144 / 4.56;
        else if (size === "1440x2016") innerPadding = 144 / 5.04;
        else if (size === "1824x1824") innerPadding = 144 / 4.56;
        else if (size === "1824x2208") innerPadding = 144 / 5.52;
        else if (size === "2016x2592") innerPadding = 144 / 6.48;
        else if (size === "2208x2976") innerPadding = 144 / 7.44;
        else if (size === "2208x3168") innerPadding = 144 / 7.92;
        else if (size === "2592x3360") innerPadding = 144 / 8.4;
        else if (size === "2592x3744") innerPadding = 144 / 9.36;
        else innerPadding = null;
      }

      const borderSize = innerPadding;
      console.log("bordersize---", borderSize);

      const frmcolor1 = appState.frameColor;

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

      resolve(newImg);
      logAllAddedElements();

    }, { crossOrigin: "anonymous" });
  });
}

// ============================================
// 3D PREVIEW THUMBNAIL HELPERS
// ============================================
function waitForAnimationFrames(frameCount = 2) {
  return new Promise((resolve) => {
    const step = () => {
      if (frameCount <= 0) { resolve(); return; }
      frameCount--;
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}

function waitForMilliseconds(delay) {
  return new Promise((resolve) => setTimeout(resolve, delay));
}

async function getBestThumbnailPreviewSource(fallbackSource = null) {
  try {
    if (typeof window.threedpreview === "function") {
      await window.threedpreview();
    } else if (typeof window.open3dpreview === "function") {
      await window.open3dpreview();
    } else if (typeof window.updateThreeDPreview === "function") {
      window.updateThreeDPreview();
    } else if (typeof window["3dpreview"] === "function") {
      await window["3dpreview"]();
    }

    await waitForAnimationFrames(4);
    await waitForMilliseconds(120);

    if (typeof window.captureThreePreview === "function") {
      const capture = window.captureThreePreview();
      if (capture) {
        return capture;
      }
    }
  } catch (error) {
    console.error("Failed to build 3D preview thumbnail source:", error);
  }

  try {
    if (typeof canvas !== "undefined" && canvas && typeof canvas.toDataURL === "function") {
      const canvasDataUrl = canvas.toDataURL({ format: "jpeg", quality: 0.92 });
      if (canvasDataUrl && canvasDataUrl.startsWith("data:image/")) {
        return canvasDataUrl;
      }
    }
  } catch (canvasErr) {
    console.error("Failed to capture canvas for thumbnail:", canvasErr);
  }

  return fallbackSource;
}

async function exportFullDivAsImage(customerId, sessionId, frmcolor) {
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
const frmbordercolor = frmcolor;
    const paddedDataURL = await addPaddingToDataURL(dataURL, 0, frmbordercolor);

    // Use 3D preview capture as thumbnail when available, otherwise fall back to paddedDataURL
    const thumbnailSource = await getBestThumbnailPreviewSource(paddedDataURL);
    const res = await fetch(thumbnailSource);
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
    imgElement.src = paddedDataURL;
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
function addPaddingToDataURL(dataURL, padding, bgColor) {
  return new Promise((resolve) => {
    const img = new Image();
    img.src = dataURL;
    img.onload = () => {
      const canvas = document.createElement("canvas");
      canvas.width = img.width + padding * 2;
      canvas.height = img.height + padding * 2;
      const ctx = canvas.getContext("2d");

      if(bgColor === "#FFFFFF"){
        ctx.fillStyle = "#000000";
      } 
      else {
        ctx.fillStyle = "#FFFFFF";
      }
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
  const afterSavePopup = document.querySelector("#aftersavepopup"); // Get the after save popup
  
   if (savepopup) savepopup.style.display = "flex";
  if (afterSavePopup) afterSavePopup.style.display = "none"; // Ensure it's hidden initially

const savepopuptitle = document.querySelector(".save-image-title");
const savepopupicon = document.querySelector(".save-image-icon");
const savepopuptext = document.querySelector(".save-image-text");

if (savepopupicon) savepopupicon.style.display = "flex";

savepopuptitle.textContent = "Boosting Image";
savepopuptext.textContent = "Boosting resolution for maximum clarity";

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
  if (imageUrl) formData.append("imageUrl", imageUrl);
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
      body: formData,
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
   
      canvas.clear();
      // set white background
canvas.setBackgroundColor('#ffffff', canvas.renderAll.bind(canvas));
      appState.uploadedImage = img;
      appState.uploadedImage.set({
        selectable: true,
        hasBorders: false,
        hasControls: false,
        lockRotation: true,
        lockScalingFlip: true,
        lockUniScaling: true,
        originX: "center",
        originY: "center",
        clipPath: appState.clipPath || null,
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

      const imgfileWElement = document.getElementById("img-file-w");
      const imgfileHElement = document.getElementById("img-file-h");

     document.getElementById("img-file-w").textContent =
        appState.uploadedImage.width || 0;
      document.getElementById("img-file-h").textContent =
        appState.uploadedImage.height || 0;
 await updatePositionInfo();

      const slider = document.getElementById("zoomSlider");
      if (slider) {
       
        updateSliderBackground(slider);
        syncZoomSlider(); // Sync zoom slider after upscale
      }



  
      // 🔹 Inline DPI display logic
      // const dpiElement = document.querySelector(".dpi-num");
      // const iconElement = document.querySelector(".dpi-state-icon");
      const boostBtn = document.querySelector(".boost-img-btn");
      const currentDpi = Number((appState.dpi || 0).toFixed(2));
      if ( boostBtn) {
  if (currentDpi < 30) {
  // dpiElement.textContent = `Needs Upscale`;
  //   dpiElement.style.color = "red";

  //   iconElement.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
  //     <path d="M9.9891 0C4.49317 0 0 4.49317 0 9.9891C0 15.4859 4.49317 20 9.9891 20C15.485 20 20 15.5068 20 9.9891C20 4.47115 15.5068 0 9.9891 0ZM9.9891 18.3208C5.40912 18.3208 1.67946 14.5911 1.67946 10.0111C1.67946 5.43115 5.40912 1.70148 9.9891 1.70148C14.5691 1.70148 18.2987 5.43115 18.2987 10.0111C18.3207 14.5911 14.5909 18.3208 9.9891 18.3208Z" fill="#FF0606"/>
  //     <path d="M10.1207 4.56252C9.74952 4.56252 9.44421 4.69326 9.20466 4.93365C8.98621 5.1732 8.85547 5.52239 8.85547 5.93651C8.85547 6.24185 8.8774 6.72177 8.92126 7.41931L9.16081 10.9307C9.20466 11.4106 9.29154 11.7379 9.37926 11.9774C9.48806 12.2389 9.70651 12.3696 10.0118 12.3696C10.3172 12.3696 10.5137 12.2389 10.6444 11.9774C10.7532 11.7379 10.841 11.3887 10.8629 10.9526L11.1682 7.33156C11.2121 7.0043 11.2121 6.65511 11.2121 6.34977C11.2121 5.78297 11.1463 5.34691 10.9936 5.04073C10.884 4.7371 10.5787 4.56252 10.1207 4.56252Z" fill="#FF0606"/>
  //     <path d="M10.0549 13.4844C9.72761 13.4844 9.44421 13.5932 9.20466 13.8336C8.96511 14.0731 8.85547 14.3354 8.85547 14.6627C8.85547 15.0338 8.9862 15.3391 9.2266 15.5348C9.46615 15.7313 9.75039 15.8402 10.0768 15.8402C10.3821 15.8402 10.6655 15.7313 10.9059 15.5129C11.1455 15.2944 11.277 14.6408 11.277 14.6408C11.277 14.3135 11.1682 14.0301 10.9278 13.7906C10.6655 13.5932 10.3813 13.4844 10.0549 13.4844Z" fill="#FF0606"/>
  //   </svg>`;

    boostBtn.style.display = "flex";
    boostBtn.classList.add("show");
  } else if (currentDpi > 300){
  //  dpiElement.textContent = `Good To Print`;
  //   dpiElement.style.color = "green";

  //   iconElement.innerHTML = `<svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
  //     <path d="M10 0C4.48421 0 0 4.48421 0 10C0 15.5158 4.48421 20 10 20C15.5158 20 20 15.5158 20 10C20 4.48421 15.5158 0 10 0ZM10 17.8105C5.68421 17.8105 2.18947 14.2947 2.18947 10C2.18947 5.70526 5.68421 2.18947 10 2.18947C14.3158 2.18947 17.8105 5.68421 17.8105 10C17.8105 14.3158 14.3158 17.8105 10 17.8105Z" fill="#1B8600"/>
  //     <path d="M12.7139 6.92258L8.90337 10.7542L7.28232 9.13311C6.86127 8.71205 6.16653 8.71205 5.74548 9.13311C5.32442 9.55416 5.32442 10.2489 5.74548 10.6699L8.14548 13.0699C8.356 13.2805 8.62969 13.3857 8.92443 13.3857C9.21916 13.3857 9.49285 13.2805 9.70337 13.0699L14.2928 8.48047C14.7139 8.05942 14.7139 7.36469 14.2928 6.94363C13.8507 6.50153 13.156 6.50153 12.7139 6.92258Z" fill="#1B8600"/>
  //   </svg>`;

    boostBtn.classList.remove("show");
    if (!boostBtn.classList.contains("show")) {
      boostBtn.style.display = "none";
    }
  } else if (currentDpi == 0) {
 boostBtn.classList.remove("show");
    setTimeout(() => {
      if (!boostBtn.classList.contains("show")) {
        boostBtn.style.display = "none"; 
         document.querySelector(".image-conform-btn").style.display = "flex";
      }
    }, 300);
  }
      }

    });

        if (result?.message === "We can not upscale this image further. Please try a different image."
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

  }
  catch (err) {
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


document.querySelector(".boost-img-btn").addEventListener("click", (e) => {
 

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
      printWidth:  printWidthdata,
      printHeight: printHeightdata,
      imageUrl: dataMainImg
    });
  } else if (dataMainImg.startsWith("data:image")) {
    const file = base64ToFile(dataMainImg, "uploaded.jpeg");
    upscaleAndFixDPI({
      customerId: userId,
      sessionId: sessionId,
      dpi: dpidata,
      printWidth:  printWidthdata,
      printHeight: printHeightdata,
      file: file
    });
  } else {
    console.error("Invalid data-main-img format.");
  }
});

function getCroppedCanvas() {
  let innerPadding;
  
    const frnheight = appState.orgHeight;
  const frmwidth = appState.orgWidth;
  const size = `${appState.selectedWidth}x${appState.selectedHeight}`;
if (window.innerWidth < 680) {
     if (size === "1056x1248") {
    innerPadding = 144 / 6.24;
    } else if (size === "1152x1440") {
    innerPadding = 144 / 7.2;
    } else if (size === "1344x1632") {
    innerPadding = 144 / 8.16;
    } else if (size === "1440x1440") {
    innerPadding = 144 / 7.2;
    } else if (size === "1440x1824") {
    innerPadding = 144 / 9.12;
    } else if (size === "1440x2016") {
    innerPadding = 144 / 10.08;
    } else if (size === "1824x1824") {
    innerPadding = 144 / 9.12;
    } else if (size === "1824x2208") {
    innerPadding = 144 / 11.04;
    } else if (size === "2016x2592") {
    innerPadding = 144 / 12.96;
    } else if (size === "2208x2976") {
    innerPadding = 144 / 14.88;
    } else if (size === "2208x3168") {
    innerPadding = 144 / 15.84;
    } else if (size === "2592x3360") {
    innerPadding = 144 / 16.8;
    } else if (size === "2592x3744") {
    innerPadding = 144 / 18.72;
    } else {
    innerPadding = null;
    }
} else {
     if (size === "1056x1248") {
    innerPadding = 144 / 3.12;
    } else if (size === "1152x1440") {
    innerPadding = 144 / 3.6;
    } else if (size === "1344x1632") {
    innerPadding = 144 / 4.08;
    } else if (size === "1440x1440") {
    innerPadding = 144 / 3.6;
    } else if (size === "1440x1824") {
    innerPadding = 144 / 4.56;
    } else if (size === "1440x2016") {
    innerPadding = 144 / 5.04;
    } else if (size === "1824x1824") {
    innerPadding = 144 / 4.56;
    } else if (size === "1824x2208") {
    innerPadding = 144 / 5.52;
    } else if (size === "2016x2592") {
    innerPadding = 144 / 6.48;
    } else if (size === "2208x2976") {
    innerPadding = 144 / 7.44;
    } else if (size === "2208x3168") {
    innerPadding = 144 / 7.92;
    } else if (size === "2592x3360") {
    innerPadding = 144 / 8.4;
    } else if (size === "2592x3744") {
    innerPadding = 144 / 9.36;
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
   

    const imgRatioEl = document.getElementById("img-ratio");
    if (!imgRatioEl) {
      console.warn("⚠️ No element found with id 'img-ratio'");
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
      } else {
        label.style.border = "1px solid #333";
      }
    });

    if (!matchFound) {
      console.warn("⚠️ No exact match found for ratio:", ratioValue);
    } else {
    

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

    const options = document.querySelectorAll("#frameSizeOptions label.frame-size-btn input");
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

    if (!found) {
      console.warn(`❌ Related option not found for "${targetValue}"`);
    }
  }

  const ratioCheckInterval = setInterval(() => {
    const done = highlightMatchingOption();
    if (done) {
      clearInterval(ratioCheckInterval);
    } 
  }, 300);
});



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

document.addEventListener("DOMContentLoaded", function () {
  const items = document.querySelectorAll(".frame-color");

  items.forEach(item => {
    const header = item.querySelector(".pdp-option-title-wrap.is-color");
    const content = item.querySelector(".frame-color-options");
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


// function exportInnerCanvasImage(customerId, sessionId) {
//   if (typeof canvas === "undefined" || typeof appState.innerCanvas === "undefined") {
//     console.error("Canvas or innerCanvas not ready");
//     return;
//   }

//   canvas.discardActiveObject();
//   canvas.renderAll();

//   const dataURL = canvas.toDataURL({
//     left: appState.innerCanvas.left,
//     top: appState.innerCanvas.top,
//     width: appState.innerCanvas.width,
//     height: appState.innerCanvas.height,
//     format: "png",
//     multiplier: 1,
//   });

//   fetch(dataURL)
//     .then(res => res.blob())
//     .then(blob => {
//       const formData = new FormData();
//       formData.append("file", blob, "inner-canvas-image.png");
//       formData.append("customerId", customerId);
//       formData.append("sessionId", sessionId);

//       return fetch(`${window.Prompt2Prints.apiBase}/upload-image`, {
//         method: "POST",
//         body: formData,
//       });
//     })
//     .then(response => response.json())
//     .then(data => {
//       const hiddenInput = document.getElementById("production-image-data");
//       if (hiddenInput && data.cloudfrontLink) hiddenInput.value = data.cloudfrontLink;
//     })
//     .catch(err => {
//       console.error("Error sending to API:", err);
//     });
// }
// function exportFullDivAsImage() {
//     const parentDiv = document.querySelector('.back-image'); // parent div of your canvas
//     if (!parentDiv) {
//         console.error('No element with class .canvas-parent found');
//         return;
//     }

//     // Optional: hide Fabric.js object controls temporarily
//     canvas.discardActiveObject();
//     canvas.renderAll();
//     canvas.getObjects().forEach(obj => obj.set({ selectable: false, evented: false }));

//     // Use html2canvas on the parent div
//     html2canvas(parentDiv, { allowTaint: true, useCORS: true }).then(canvasImage => {
//         const link = document.createElement('a');
//         link.download = 'full-div-image.png';
//         link.href = canvasImage.toDataURL('image/png');
//         link.click();

//         // Restore Fabric.js objects selectability
//         canvas.getObjects().forEach(obj => obj.set({ selectable: true, evented: true }));
//         canvas.renderAll();
//     }).catch(err => {
//         console.error('Error exporting full div:', err);
//         canvas.getObjects().forEach(obj => obj.set({ selectable: true, evented: true }));
//         canvas.renderAll();
//     });
// }
// Function to track image position in pixels










// document.getElementById('frame-preview').addEventListener('click', function () {
//   if (!uploadedImage) return;

//   uploadedImage.clone((clonedImg) => {

//     clonedImg.set({
//       clipPath: uploadedImage.clipPath ? uploadedImage.clipPath.clone() : null,
//       scaleX: uploadedImage.scaleX,
//       scaleY: uploadedImage.scaleY,
//       angle: uploadedImage.angle,
//       left: uploadedImage.left,
//       top: uploadedImage.top,
//       originX: uploadedImage.originX,
//       originY: uploadedImage.originY,
//     });

//     // Create temp canvas same size as main canvas
//     const tempCanvas = new fabric.StaticCanvas();
//     tempCanvas.setWidth(canvas.getWidth());
//     tempCanvas.setHeight(canvas.getHeight());

//     tempCanvas.add(clonedImg);
//     tempCanvas.renderAll();

//     // Export only what user sees (no frame, no shadow)
//     const dataUrl = tempCanvas.toDataURL({
//       format: 'png',
//       quality: 1,
//       multiplier: 1, // export scale factor
//     });

//     // Save into hidden input
//     const finalInput = document.getElementById('final-image-data');
//     if (finalInput) {
//       finalInput.value = dataUrl;
//     }
//   });
// });

// -------------------------------------------------------------------------------------

// // Finalize
// document.getElementById('finalize-image').addEventListener('click', function () {
//   canvas.discardActiveObject();
//   canvas.renderAll();

//   const dataUrl = canvas.toDataURL({
//     format: 'png',
//     quality: 1,
//   });

//   document.cookie = `pdp-final-image=${encodeURIComponent(dataUrl)}; path=/; max-age=86400`;
//   alert('Final image stored in cookie as "pdp-final-image".');
// });

// Orientation change
//   document.getElementById('frameOrientationOptions').addEventListener('change', function (e) {
//     if (e.target.name === 'frameOrientation') {
//       const orientation = e.target.value;

//       if (orientation === 'portrait') {
//         updateFrameFromPixels(
//           Math.min(selectedWidth, selectedHeight),
//           Math.max(selectedWidth, selectedHeight)
//         );
//       } else {
//         updateFrameFromPixels(
//           Math.max(selectedWidth, selectedHeight),
//           Math.min(selectedWidth, selectedHeight)
//         );
//       }

//       if (uploadedImage) {
//         uploadedImage.clipPath = clipPath;
//         canvas.add(uploadedImage);
//         fitImageToFrame(false);
//       }
//     }
//   });

// Frame color change
// document.getElementById('frameColorOptions').addEventListener('change', function (e) {
//   if (e.target.name === 'frameColor') {
//     const selectedColor = e.target.value;
//     const frameColor = frameColorMap[selectedColor] || '#000000';

//     if (outerFrame) {
//       outerFrame.set('fill', frameColor);
//       canvas.requestRenderAll();
//     }
//   }
// });
document.querySelector('.frm-note-close').addEventListener('click', () => {
  document.querySelector('.frm-image-note').style.display = 'none';
});

