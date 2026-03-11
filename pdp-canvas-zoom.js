const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;

// ============================
// CANVAS ZOOM FUNCTIONALITY
// ============================
class CanvasZoom {
    constructor(canvas, containerSelector = '.canvas-wrap') {
        this.canvas = canvas;
        this.container = document.querySelector(containerSelector);
        this.lowerCanvas = document.getElementById('image-canvas');
        this.upperCanvas = this.container.querySelector('.upper-canvas');
        
        // Zoom properties
        this.scale = 1;
        this.minScale = 0.1;
        this.maxScale = 10;
        this.zoomStep = 0.1;
        
        // Pan properties
        this.panning = false;
        this.startX = 0;
        this.startY = 0;
        this.offsetX = 0;
        this.offsetY = 0;
        
        // Touch-specific properties
        this.touchStartDistance = 0;
        this.touchStartScale = 1;
        this.lastTouchX = 0;
        this.lastTouchY = 0;
        this.touchStartX = 0;
        this.touchStartY = 0;
        
        // Move toggle property - INITIALLY LOCKED
        this.moveEnabled = false;
        
        // Visual indicator properties
        this.indicator = null;
        this.indicatorTimeout = null;
        this.moveIconBtn = null;
        
        // Tooltip properties
        this.tooltip = null;
        this.tooltipTimeout = null;
        this.tooltipEnabled = true;
        
        // Ensure container has proper styling
        this.container.style.overflow = 'hidden';
        this.container.style.position = 'relative';
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.createMoveIndicator();
        this.createTooltip();
        
        // Set initial state to locked
        this.setMoveEnabled(false);
        
        // Calculate and apply perfect centered zoom on load
        setTimeout(() => {
            this.calculateAndApplyOptimalZoom();
        }, 100);
    }
    
    /**
     * Calculate optimal zoom - Scale based on LARGER canvas dimension
     */
    calculateAndApplyOptimalZoom() {
        try {
            // Get canvas dimensions
            let canvasWidth, canvasHeight;
            
            if (this.canvas && this.canvas.width && this.canvas.height) {
                canvasWidth = this.canvas.width;
                canvasHeight = this.canvas.height;
            } else if (this.lowerCanvas) {
                canvasWidth = this.lowerCanvas.width || 400;
                canvasHeight = this.lowerCanvas.height || 400;
            } else {
                canvasWidth = 400;
                canvasHeight = 400;
            }
            
            // Get container dimensions
            const containerRect = this.container.getBoundingClientRect();
            const containerWidth = containerRect.width;
            const containerHeight = containerRect.height;
          
            // Determine which canvas dimension is larger
            const isCanvasWider = canvasWidth > canvasHeight;
            const isContainerWider = containerWidth > containerHeight;
           
            // NEW LOGIC: Scale based on LARGER dimension
            let optimalScale;
            
            if (isCanvasWider) {
                // Canvas is wider than tall → scale based on WIDTH
                // Use container's smaller dimension to fit
                const minContainer = Math.min(containerWidth, containerHeight);
                optimalScale = minContainer / canvasWidth;
            } else {
                // Canvas is taller than wide → scale based on HEIGHT
                // Use container's smaller dimension to fit
                const minContainer = Math.min(containerWidth, containerHeight);
                optimalScale = minContainer / canvasHeight;
            }
            
            optimalScale = optimalScale * 0.9; // 90% padding
            
            // Clamp the scale
            optimalScale = Math.max(this.minScale, Math.min(optimalScale, this.maxScale));
            
            // Calculate PERFECT CENTERING ON BOTH AXES
            const scaledWidth = canvasWidth * optimalScale;
            const scaledHeight = canvasHeight * optimalScale;
            
            this.offsetX = (containerWidth - scaledWidth) / 2;
            this.offsetY = (containerHeight - scaledHeight) / 2;
            this.scale = optimalScale;
            
            this.updateTransform();
            
          
            
        } catch (error) {
            console.error('Error calculating optimal zoom:', error);
            // Fallback
            this.scale = 1;
            this.offsetX = 0;
            this.offsetY = 0;
            this.updateTransform();
        }
    }
    
    /**
     * Alternative: Scale based on container's matching dimension
     * If canvas is wider, use container width. If taller, use container height.
     */
    calculateAndApplyMatchingZoom() {
        try {
            // Get canvas dimensions
            let canvasWidth, canvasHeight;
            
            if (this.canvas && this.canvas.width && this.canvas.height) {
                canvasWidth = this.canvas.width;
                canvasHeight = this.canvas.height;
            } else if (this.lowerCanvas) {
                canvasWidth = this.lowerCanvas.width || 400;
                canvasHeight = this.lowerCanvas.height || 400;
            } else {
                canvasWidth = 400;
                canvasHeight = 400;
            }
            
            // Get container dimensions
            const containerRect = this.container.getBoundingClientRect();
            const containerWidth = containerRect.width;
            const containerHeight = containerRect.height;
            
            
            // Determine canvas orientation
            const canvasAspectRatio = canvasWidth / canvasHeight;
            const containerAspectRatio = containerWidth / containerHeight;
            
            
            let optimalScale;
            
            // Scale to fit based on matching dimensions
            if (canvasAspectRatio > containerAspectRatio) {
                // Canvas is relatively wider than container → fit to container width
                optimalScale = containerWidth / canvasWidth;
              
            } else {
                // Canvas is relatively taller than container → fit to container height
                optimalScale = containerHeight / canvasHeight;
            }
            
            optimalScale = optimalScale * 0.9; // 90% padding
            
            // Clamp the scale
            optimalScale = Math.max(this.minScale, Math.min(optimalScale, this.maxScale));
            
            // Calculate PERFECT CENTERING
            const scaledWidth = canvasWidth * optimalScale;
            const scaledHeight = canvasHeight * optimalScale;
            
            this.offsetX = (containerWidth - scaledWidth) / 2;
            this.offsetY = (containerHeight - scaledHeight) / 2;
            this.scale = optimalScale;
            
            this.updateTransform();
           
        } catch (error) {
            console.error('Error calculating matching zoom:', error);
            // Fallback
            this.scale = 1;
            this.offsetX = 0;
            this.offsetY = 0;
            this.updateTransform();
        }
    }
    
    /**
     * NEW: Scale based on CONTAINER's larger dimension (alternative approach)
     */
    calculateAndApplyContainerBasedZoom() {
        try {
            // Get canvas dimensions
            let canvasWidth, canvasHeight;
            
            if (this.canvas && this.canvas.width && this.canvas.height) {
                canvasWidth = this.canvas.width;
                canvasHeight = this.canvas.height;
            } else if (this.lowerCanvas) {
                canvasWidth = this.lowerCanvas.width || 400;
                canvasHeight = this.lowerCanvas.height || 400;
            } else {
                canvasWidth = 400;
                canvasHeight = 400;
            }
            
            // Get container dimensions
            const containerRect = this.container.getBoundingClientRect();
            const containerWidth = containerRect.width;
            const containerHeight = containerRect.height;
            
            // Determine which container dimension is larger
            const isContainerWider = containerWidth > containerHeight;
            
            let optimalScale;
            
            if (isContainerWider) {
                // Container is wider → scale canvas to container width
                optimalScale = containerWidth / canvasWidth;
            } else {
                // Container is taller → scale canvas to container height
                optimalScale = containerHeight / canvasHeight;
            }
            
            optimalScale = optimalScale * 0.9; // 90% padding
            
            // Clamp the scale
            optimalScale = Math.max(this.minScale, Math.min(optimalScale, this.maxScale));
            
            // Calculate PERFECT CENTERING
            const scaledWidth = canvasWidth * optimalScale;
            const scaledHeight = canvasHeight * optimalScale;
            
            this.offsetX = (containerWidth - scaledWidth) / 2;
            this.offsetY = (containerHeight - scaledHeight) / 2;
            this.scale = optimalScale;
            
            this.updateTransform();
           
            
        } catch (error) {
            console.error('Error calculating container-based zoom:', error);
            // Fallback
            this.scale = 1;
            this.offsetX = 0;
            this.offsetY = 0;
            this.updateTransform();
        }
    }
    
    /**
     * NEW: Scale based on BOTH dimensions independently (fill container)
     */
    calculateAndApplyFillZoom() {
        try {
            // Get canvas dimensions
            let canvasWidth, canvasHeight;
            
            if (this.canvas && this.canvas.width && this.canvas.height) {
                canvasWidth = this.canvas.width;
                canvasHeight = this.canvas.height;
            } else if (this.lowerCanvas) {
                canvasWidth = this.lowerCanvas.width || 400;
                canvasHeight = this.lowerCanvas.height || 400;
            } else {
                canvasWidth = 400;
                canvasHeight = 400;
            }
            
            // Get container dimensions
            const containerRect = this.container.getBoundingClientRect();
            const containerWidth = containerRect.width;
            const containerHeight = containerRect.height;
            
            // Calculate scale for width and height independently
            const scaleX = containerWidth / canvasWidth;
            const scaleY = containerHeight / canvasHeight;
            
            // Use the smaller scale to ensure canvas fits (with padding)
            let optimalScale = Math.min(scaleX, scaleY) * 0.9;
            
            // Clamp the scale
            optimalScale = Math.max(this.minScale, Math.min(optimalScale, this.maxScale));
            
            // Calculate PERFECT CENTERING
            const scaledWidth = canvasWidth * optimalScale;
            const scaledHeight = canvasHeight * optimalScale;
            
            this.offsetX = (containerWidth - scaledWidth) / 2;
            this.offsetY = (containerHeight - scaledHeight) / 2;
            this.scale = optimalScale;
            
            this.updateTransform();
            
           
            
        } catch (error) {
            console.error('Error calculating fill zoom:', error);
            // Fallback
            this.scale = 1;
            this.offsetX = 0;
            this.offsetY = 0;
            this.updateTransform();
        }
    }
    
    /**
     * NEW: Smart scaling - automatically chooses best method
     */
    calculateAndApplySmartZoom() {
        try {
            // Get canvas dimensions
            let canvasWidth, canvasHeight;
            
            if (this.canvas && this.canvas.width && this.canvas.height) {
                canvasWidth = this.canvas.width;
                canvasHeight = this.canvas.height;
            } else if (this.lowerCanvas) {
                canvasWidth = this.lowerCanvas.width || 400;
                canvasHeight = this.lowerCanvas.height || 400;
            } else {
                canvasWidth = 400;
                canvasHeight = 400;
            }
            
            // Get container dimensions
            const containerRect = this.container.getBoundingClientRect();
            const containerWidth = containerRect.width;
            const containerHeight = containerRect.height;
            
            // Calculate different scale options
            const scaleToWidth = (containerWidth / canvasWidth) * 0.9;
            const scaleToHeight = (containerHeight / canvasHeight) * 0.9;
            
            // Choose the scale that results in better visibility
            // (the one that makes the canvas larger but still fits)
            let optimalScale;
            
            if (canvasWidth >= canvasHeight) {
                // Canvas is wider or square → prioritize width scaling
                optimalScale = scaleToWidth;
            } else {
                // Canvas is taller → prioritize height scaling
                optimalScale = scaleToHeight;
            }
            
            // Ensure the chosen scale also fits the other dimension
            const scaledWidth = canvasWidth * optimalScale;
            const scaledHeight = canvasHeight * optimalScale;
            
            if (scaledWidth > containerWidth) {
                optimalScale = (containerWidth / canvasWidth) * 0.9;
            }
            
            if (scaledHeight > containerHeight) {
                optimalScale = (containerHeight / canvasHeight) * 0.9;
            }
            
            // Recalculate with adjusted scale
            const finalScaledWidth = canvasWidth * optimalScale;
            const finalScaledHeight = canvasHeight * optimalScale;
            
            // Clamp the scale
            optimalScale = Math.max(this.minScale, Math.min(optimalScale, this.maxScale));
            
            this.offsetX = (containerWidth - finalScaledWidth) / 2;
            this.offsetY = (containerHeight - finalScaledHeight) / 2;
            this.scale = optimalScale;
            
            this.updateTransform();
         
            
        } catch (error) {
            console.error('Error calculating smart zoom:', error);
            // Fallback
            this.scale = 1;
            this.offsetX = 0;
            this.offsetY = 0;
            this.updateTransform();
        }
    }
    
    /**
     * Recalculate zoom (call this when canvas changes)
     */
    recalculateZoom() {
        // Use the smart zoom calculation by default
        this.calculateAndApplySmartZoom();
    }
    
    /**
     * Center the canvas at current scale
     */
    centerCanvas() {
        if (!this.container || !this.lowerCanvas) return;
        
        const containerRect = this.container.getBoundingClientRect();
        const containerWidth = containerRect.width;
        const containerHeight = containerRect.height;
        
        const canvasWidth = this.canvas?.width || this.lowerCanvas?.width || 400;
        const canvasHeight = this.canvas?.height || this.lowerCanvas?.height || 400;
        
        const scaledWidth = canvasWidth * this.scale;
        const scaledHeight = canvasHeight * this.scale;
        
        // Center on both axes
        this.offsetX = (containerWidth - scaledWidth) / 2;
        this.offsetY = (containerHeight - scaledHeight) / 2;
        
        this.updateTransform();
        
    }
    
    /**
     * Fit canvas to container with different strategies
     */
    fitToContainer(strategy = 'smart', paddingPercent = 0.9) {
        try {
            // Store original padding for calculations
            const originalPadding = 0.9;
            
            switch(strategy) {
                case 'width':
                    // Scale based on width
                    this.calculateAndApplyOptimalZoom();
                    break;
                    
                case 'height':
                    // Scale based on height
                    this.calculateAndApplyContainerBasedZoom();
                    break;
                    
                case 'fill':
                    // Fill container (might crop)
                    this.calculateAndApplyFillZoom();
                    break;
                    
                case 'match':
                    // Match aspect ratios
                    this.calculateAndApplyMatchingZoom();
                    break;
                    
                case 'smart':
                default:
                    // Smart automatic scaling
                    this.calculateAndApplySmartZoom();
                    break;
            }
            
            // Apply custom padding if different from default
            if (paddingPercent !== 0.9) {
                const canvasWidth = this.canvas?.width || this.lowerCanvas?.width || 400;
                const canvasHeight = this.canvas?.height || this.lowerCanvas?.height || 400;
                const containerRect = this.container.getBoundingClientRect();
                
                // Adjust scale with custom padding
                this.scale = this.scale * (paddingPercent / originalPadding);
                
                // Re-center with new scale
                const scaledWidth = canvasWidth * this.scale;
                const scaledHeight = canvasHeight * this.scale;
                
                this.offsetX = (containerRect.width - scaledWidth) / 2;
                this.offsetY = (containerRect.height - scaledHeight) / 2;
                
                this.updateTransform();
            }
            
        } catch (error) {
            console.error('Error in fitToContainer:', error);
        }
    }
    
    createMoveIndicator() {
        // Create a visual indicator for move state
        this.indicator = document.createElement('div');
        this.indicator.style.cssText = `
            position: absolute;
            top: 10px;
            left: 50%;
            transform: translateX(-50%);
            z-index: 1001;
            background: rgba(0, 0, 0, 0.8);
            color: white;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            opacity: 0;
            transition: opacity 0.3s;
            pointer-events: none;
            white-space: nowrap;
            text-align: center;
            max-width: 90%;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            border: 1px solid rgba(255,255,255,0.1);
        `;
        this.container.appendChild(this.indicator);
    }
    
    createTooltip() {
        // Create a tooltip element
        this.tooltip = document.createElement('div');
        this.tooltip.style.cssText = `
            position: absolute;
            z-index: 1002;
            background: rgba(0, 0, 0, 0.85);
            color: white;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 400;
            opacity: 0;
            transition: opacity 0.2s, transform 0.2s;
            pointer-events: none;
            white-space: nowrap;
            max-width: 300px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            border: 1px solid rgba(255,255,255,0.1);
            transform: translateY(-5px);
            text-align: center;
        `;
        document.body.appendChild(this.tooltip);
    }
    
    showTooltip(text, x, y) {
        if (!this.tooltipEnabled || !this.tooltip) return;
        
        this.tooltip.textContent = text;
        this.tooltip.style.left = x + 'px';
        this.tooltip.style.top = y + 'px';
        this.tooltip.style.opacity = '1';
        this.tooltip.style.transform = 'translateY(0)';
        
        // Clear previous timeout
        if (this.tooltipTimeout) {
            clearTimeout(this.tooltipTimeout);
        }
        
        // Auto-hide tooltip after 2 seconds on desktop
        // On mobile, hide immediately on touch move
        if (!isTouchDevice) {
            this.tooltipTimeout = setTimeout(() => {
                this.hideTooltip();
            }, 2000);
        }
    }
    
    hideTooltip() {
        if (!this.tooltip) return;
        
        this.tooltip.style.opacity = '0';
        this.tooltip.style.transform = 'translateY(-5px)';
        
        if (this.tooltipTimeout) {
            clearTimeout(this.tooltipTimeout);
        }
    }
    
    showIndicator(text, duration = 2000) {
        if (!this.indicator) return;
        
        this.indicator.textContent = text;
        this.indicator.style.opacity = '1';
        
        // Clear previous timeout
        if (this.indicatorTimeout) {
            clearTimeout(this.indicatorTimeout);
        }
        
        // Hide after duration
        this.indicatorTimeout = setTimeout(() => {
            this.indicator.style.opacity = '0';
        }, duration);
    }
    
    setupEventListeners() {
        // Mouse wheel for zoom (on container)
        this.container.addEventListener('wheel', this.handleWheel.bind(this), { passive: false });
        
        // Mouse down for panning (on upper canvas)
        this.upperCanvas.addEventListener('mousedown', this.handleMouseDown.bind(this));
        
        // Mouse move for panning
        document.addEventListener('mousemove', this.handleMouseMove.bind(this));
        
        // Mouse up for panning
        document.addEventListener('mouseup', this.handleMouseUp.bind(this));
        
        // Right-click to toggle move
        this.upperCanvas.addEventListener('contextmenu', this.handleRightClick.bind(this));
        
        // Also listen for right-click on the lower canvas
        this.lowerCanvas.addEventListener('contextmenu', this.handleRightClick.bind(this));

        // Keyboard shortcut for toggling move
        document.addEventListener('keydown', (e) => {
            // Only trigger if not in an input field
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.isContentEditable) return;
            
            if (e.key === 'm' || e.key === 'M') {
                e.preventDefault();
                this.toggleMove();
            }
            
            // NEW: Center with 'C' key
            if (e.key === 'c' || e.key === 'C') {
                e.preventDefault();
                this.centerCanvas();
            }
        });
        
        // Touch events for mobile
        if (isTouchDevice) {
            // Touch start for both panning and toggle
            this.upperCanvas.addEventListener('touchstart', this.handleTouchStart.bind(this), { passive: false });
            
            // Touch move for panning and pinch zoom
            this.upperCanvas.addEventListener('touchmove', this.handleTouchMove.bind(this), { passive: false });
            
            // Touch end
            this.upperCanvas.addEventListener('touchend', this.handleTouchEnd.bind(this));
            
            // Long press to toggle move (similar to right-click)
            this.setupLongPress();
            
            // Also setup for lower canvas
            this.lowerCanvas.addEventListener('touchstart', this.handleTouchStart.bind(this), { passive: false });
            this.lowerCanvas.addEventListener('touchmove', this.handleTouchMove.bind(this), { passive: false });
            this.lowerCanvas.addEventListener('touchend', this.handleTouchEnd.bind(this));
            
            // Hide tooltip on touch move
            document.addEventListener('touchmove', () => {
                this.hideTooltip();
            });
            
            // Also hide on touch start (optional)
            document.addEventListener('touchstart', () => {
                // Small delay to allow user to see the tooltip briefly
                setTimeout(() => {
                    this.hideTooltip();
                }, 500);
            });
        }
    }
    
    setupLongPress() {
        let pressTimer;
        const longPressDelay = 800; // 800ms for long press
        
        const startPress = (e) => {
            if (!this.moveEnabled && e.touches.length === 1) {
                pressTimer = setTimeout(() => {
                    this.toggleMove();
                    e.preventDefault();
                    e.stopPropagation();
                }, longPressDelay);
            }
        };
        
        const cancelPress = () => {
            if (pressTimer) {
                clearTimeout(pressTimer);
                pressTimer = null;
            }
        };
        
        this.upperCanvas.addEventListener('touchstart', startPress, { passive: false });
        this.lowerCanvas.addEventListener('touchstart', startPress, { passive: false });
        
        this.upperCanvas.addEventListener('touchmove', cancelPress);
        this.lowerCanvas.addEventListener('touchmove', cancelPress);
        
        this.upperCanvas.addEventListener('touchend', cancelPress);
        this.lowerCanvas.addEventListener('touchend', cancelPress);
        this.upperCanvas.addEventListener('touchcancel', cancelPress);
        this.lowerCanvas.addEventListener('touchcancel', cancelPress);
    }
    
    handleTouchStart(e) {
        if (!this.moveEnabled) return;
        
        e.preventDefault();
        e.stopPropagation();
        
        const touches = e.touches;
        
        if (touches.length === 1) {
            // Single touch for panning
            this.panning = true;
            const touch = touches[0];
            this.startX = touch.clientX - this.offsetX;
            this.startY = touch.clientY - this.offsetY;
            this.lastTouchX = touch.clientX;
            this.lastTouchY = touch.clientY;
            this.touchStartX = touch.clientX;
            this.touchStartY = touch.clientY;
            
            // Update cursor for visual feedback
            this.upperCanvas.style.cursor = 'grabbing';
            this.lowerCanvas.style.cursor = 'grabbing';
        } else if (touches.length === 2 && this.moveEnabled) {
            // Two touches for pinch zoom
            this.panning = false;
            const touch1 = touches[0];
            const touch2 = touches[1];
            
            // Calculate initial distance
            const dx = touch1.clientX - touch2.clientX;
            const dy = touch1.clientY - touch2.clientY;
            this.touchStartDistance = Math.sqrt(dx * dx + dy * dy);
            this.touchStartScale = this.scale;
            
            // Calculate center point
            this.lastTouchX = (touch1.clientX + touch2.clientX) / 2;
            this.lastTouchY = (touch1.clientY + touch2.clientY) / 2;
            
            // Get container-relative coordinates
            const rect = this.container.getBoundingClientRect();
            this.touchCenterX = this.lastTouchX - rect.left;
            this.touchCenterY = this.lastTouchY - rect.top;
        }
    }
    
    handleTouchMove(e) {
        if (!this.moveEnabled) return;
        
        e.preventDefault();
        e.stopPropagation();
        
        const touches = e.touches;
        
        if (touches.length === 1 && this.panning) {
            // Single touch panning
            const touch = touches[0];
            const deltaX = touch.clientX - this.lastTouchX;
            const deltaY = touch.clientY - this.lastTouchY;
            
            this.offsetX += deltaX;
            this.offsetY += deltaY;
            
            this.lastTouchX = touch.clientX;
            this.lastTouchY = touch.clientY;
            
            this.updateTransform();
        } else if (touches.length === 2 && this.moveEnabled) {
            // Two touch pinch zoom
            const touch1 = touches[0];
            const touch2 = touches[1];
            
            // Calculate current distance
            const dx = touch1.clientX - touch2.clientX;
            const dy = touch1.clientY - touch2.clientY;
            const currentDistance = Math.sqrt(dx * dx + dy * dy);
            
            // Calculate zoom factor
            if (this.touchStartDistance > 0) {
                const zoomFactor = currentDistance / this.touchStartDistance;
                const newScale = this.touchStartScale * zoomFactor;
                
                // Clamp zoom
                if (newScale >= this.minScale && newScale <= this.maxScale) {
                    const rect = this.container.getBoundingClientRect();
                    const mouseX = this.touchCenterX;
                    const mouseY = this.touchCenterY;
                    
                    // World coords before zoom
                    const worldX = (mouseX - this.offsetX) / this.scale;
                    const worldY = (mouseY - this.offsetY) / this.scale;
                    
                    // Apply zoom
                    this.scale = newScale;
                    
                    // Keep zoom centered on pinch point
                    this.offsetX = mouseX - worldX * this.scale;
                    this.offsetY = mouseY - worldY * this.scale;
                    
                    this.updateTransform();
                }
            }
            
            // Update last position for panning during pinch
            this.lastTouchX = (touch1.clientX + touch2.clientX) / 2;
            this.lastTouchY = (touch1.clientY + touch2.clientY) / 2;
        }
    }
    
    handleTouchEnd(e) {
        if (!this.moveEnabled) return;
        
        e.preventDefault();
        e.stopPropagation();
        
        this.panning = false;
        this.touchStartDistance = 0;
        
        // Reset cursor
        this.upperCanvas.style.cursor = 'move';
        this.lowerCanvas.style.cursor = 'move';
    }
    
    handleRightClick(e) {
        e.preventDefault();
        e.stopPropagation();
        
        // Toggle move functionality
        this.toggleMove();
        
        return false;
    }
    
    toggleMove() {
        const wasEnabled = this.moveEnabled;
        this.setMoveEnabled(!wasEnabled);
        
        return this.moveEnabled;
    }
    
    setMoveEnabled(enabled) {
        this.moveEnabled = enabled;
        
        // Update cursor style based on move state
        if (enabled) {
            this.upperCanvas.style.cursor = 'move';
            this.lowerCanvas.style.cursor = 'move';
        } else {
            this.upperCanvas.style.cursor = 'default';
            this.lowerCanvas.style.cursor = 'default';
            
            // If panning is active when disabled, stop it
            if (this.panning) {
                this.panning = false;
            }
        }
        
        // Also update fabric.js canvas interaction
        if (this.canvas) {
            // When move is enabled, we want to disable object selection
            // When move is disabled, we can enable object selection
            this.canvas.selection = !enabled;
            this.canvas.defaultCursor = enabled ? 'move' : 'default';
            
            // Update cursor for all objects
            const objects = this.canvas.getObjects();
            objects.forEach(obj => {
                obj.hoverCursor = enabled ? 'move' : 'default';
                obj.moveCursor = enabled ? 'move' : 'default';
            });
        }
        
        // Update the move icon button if it exists
        this.updateMoveIcon();
    }
    
    // Method to add tooltip to a button
    addTooltipToButton(button, tooltipText) {
        if (!button || !this.tooltip) return;
        
        let showTimeout;
        let hideTimeout;
        
        button.addEventListener('mouseenter', (e) => {
            // Clear any pending hide timeout
            if (hideTimeout) {
                clearTimeout(hideTimeout);
            }
            
            // Show tooltip after a small delay
            showTimeout = setTimeout(() => {
                const rect = button.getBoundingClientRect();
                // Position tooltip above the button
                const x = rect.left + rect.width / 2;
                const y = rect.top - 10;
                
                // Center the tooltip
                this.tooltip.style.left = x + 'px';
                this.tooltip.style.top = y + 'px';
                this.tooltip.style.transform = 'translate(-50%, -100%)';
                this.tooltip.textContent = tooltipText;
                this.tooltip.style.opacity = '1';
            }, 300);
        });
        
        button.addEventListener('mouseleave', () => {
            // Clear the show timeout if mouse leaves quickly
            if (showTimeout) {
                clearTimeout(showTimeout);
            }
            
            // Hide tooltip after a small delay
            hideTimeout = setTimeout(() => {
                this.hideTooltip();
            }, 100);
        });
        
        // Also add click handler to hide tooltip immediately
        button.addEventListener('click', () => {
            this.hideTooltip();
        });
    }
    
    updateMoveIcon() {
        if (!this.moveIconBtn) return;
        
        if (this.moveEnabled) {
            // Show unlocked/hand icon
            this.moveIconBtn.innerHTML = `
               <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M8.09585 12.2506V7.27935C8.09585 6.56252 7.51475 5.98145 6.79792 5.98145C6.0811 5.98145 5.5 6.56252 5.5 7.27935V12.9966C5.5 12.9968 5.50003 12.997 5.50005 12.9972C5.50008 12.9974 5.5001 12.9976 5.5001 12.9978V15.9432C5.5001 18.0518 6.7496 19.9599 8.68235 20.8029C10.7979 21.7257 13.2022 21.7257 15.3177 20.8029C17.2505 19.9599 18.5 18.0518 18.5 15.9432V14.4895V11.3545C18.5 10.7775 18.0797 10.0112 17.2021 10.0112C16.3244 10.0112 15.8834 10.7775 15.8834 11.3545M15.8834 11.3545V14.4895M15.8834 11.3545V5.08575C15.8834 4.50878 15.4468 3.74248 14.5854 3.74248C13.7241 3.74248 13.2875 4.50878 13.2875 5.08575V10.0112V12.2506M10.6917 12.2663L10.6917 5.03543C10.6917 4.31863 10.1106 3.73752 9.39375 3.73752C8.67693 3.73752 8.09585 4.31862 8.09585 5.03545V8.83245L8.09593 12.2663M13.2875 12.3991L13.2875 3.7425C13.2875 3.1655 12.9207 2.25 11.9896 2.25C11.0585 2.25 10.6917 3.1655 10.6917 3.7425V8.0862" stroke="#00801F" stroke-width="1.25" stroke-linecap="round"/>
</svg>
            `;
         
            this.moveIconBtn.style.color = '#4CAF50';
            this.moveIconBtn.style.background = 'transparent';
            this.moveIconBtn.style.borderColor = 'transparent';
            
        } else {
            // Show locked icon
            this.moveIconBtn.innerHTML = `
               <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M8.09585 12.2506V7.27935C8.09585 6.56252 7.51475 5.98145 6.79792 5.98145C6.0811 5.98145 5.5 6.56252 5.5 7.27935V12.9966C5.5 12.9968 5.50003 12.997 5.50005 12.9972C5.50008 12.9974 5.5001 12.9976 5.5001 12.9978V15.9432C5.5001 18.0518 6.7496 19.9599 8.68235 20.8029C10.7979 21.7257 13.2022 21.7257 15.3177 20.8029C17.2505 19.9599 18.5 18.0518 18.5 15.9432V14.4895V11.3545C18.5 10.7775 18.0797 10.0112 17.2021 10.0112C16.3244 10.0112 15.8834 10.7775 15.8834 11.3545M15.8834 11.3545V14.4895M15.8834 11.3545V5.08575C15.8834 4.50878 15.4468 3.74248 14.5854 3.74248C13.7241 3.74248 13.2875 4.50878 13.2875 5.08575V10.0112V12.2506M10.6917 12.2663L10.6917 5.03543C10.6917 4.31863 10.1106 3.73752 9.39375 3.73752C8.67693 3.73752 8.09585 4.31862 8.09585 5.03545V8.83245L8.09593 12.2663M13.2875 12.3991L13.2875 3.7425C13.2875 3.1655 12.9207 2.25 11.9896 2.25C11.0585 2.25 10.6917 3.1655 10.6917 3.7425V8.0862" stroke="white" stroke-width="1.25" stroke-linecap="round"/>
</svg>
            `;
            this.moveIconBtn.style.color = 'white';
            this.moveIconBtn.style.background = 'transparent';
            this.moveIconBtn.style.borderColor = 'transparent';
            
        }
    }
    
    // Method to set the move icon button (should be called from outside)
    setMoveIconButton(button) {
        this.moveIconBtn = button;
        this.updateMoveIcon();
    }
    
    handleWheel(e) {
        if (!this.moveEnabled) {
            return; 
        }

        e.preventDefault();
        e.stopPropagation();

        const rect = this.container.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;

        const zoomFactor = e.deltaY > 0 ? 1 - this.zoomStep : 1 + this.zoomStep;
        const newScale = this.scale * zoomFactor;

        // Clamp zoom
        if (newScale < this.minScale || newScale > this.maxScale) return;

        // World coords before zoom
        const worldX = (mouseX - this.offsetX) / this.scale;
        const worldY = (mouseY - this.offsetY) / this.scale;

        // Apply zoom
        this.scale = newScale;

        // Keep zoom centered on mouse
        this.offsetX = mouseX - worldX * this.scale;
        this.offsetY = mouseY - worldY * this.scale;

        this.updateTransform();
        
    } 
    
    handleMouseDown(e) {
        // Only allow left-click panning when move is enabled
        if (e.button === 0 && this.moveEnabled) {
            this.panning = true;
            this.startX = e.clientX - this.offsetX;
            this.startY = e.clientY - this.offsetY;
            this.upperCanvas.style.cursor = 'grabbing';
            this.lowerCanvas.style.cursor = 'grabbing';
        }
    }
    
    handleMouseMove(e) {
        if (!this.panning || !this.moveEnabled) return;
        
        e.preventDefault();
        
        this.offsetX = e.clientX - this.startX;
        this.offsetY = e.clientY - this.startY;
        
        this.updateTransform();
    }
    
    handleMouseUp(e) {
        if (e.button === 0 && this.moveEnabled) {
            this.panning = false;
            this.upperCanvas.style.cursor = 'move';
            this.lowerCanvas.style.cursor = 'move';
        }
    }
    
    updateTransform() {
        const transform = `translate(${this.offsetX}px, ${this.offsetY}px) scale(${this.scale})`;
        
        // Apply transform to both canvases
        this.lowerCanvas.style.transform = transform;
        this.upperCanvas.style.transform = transform;
        
        // Update transform-origin
        this.lowerCanvas.style.transformOrigin = '0 0';
        this.upperCanvas.style.transformOrigin = '0 0';
    }
    
    // Utility methods with tooltips - MODIFIED for centered zoom
    zoomIn() {
        this.zoomAtCenter(1 + this.zoomStep);
    }
    
    zoomOut() {
        this.zoomAtCenter(1 - this.zoomStep);
    }
    
    resetZoom() {
        // Reset to optimal centered zoom instead of 1:1
        this.calculateAndApplyOptimalZoom();
    }
    
    zoomAtCenter(factor) {
        const rect = this.container.getBoundingClientRect();
        const centerX = rect.width / 2;
        const centerY = rect.height / 2;
        
        const worldX = (centerX - this.offsetX) / this.scale;
        const worldY = (centerY - this.offsetY) / this.scale;
        
        const newScale = this.scale * factor;
        
        if (newScale < this.minScale || newScale > this.maxScale) return;
        
        this.scale = newScale;
        this.offsetX = centerX - worldX * this.scale;
        this.offsetY = centerY - worldY * this.scale;
        
        this.updateTransform();
    }
    
    // Public method to lock canvas
    lockCanvas() {
        this.setMoveEnabled(false);
    }
    
    // Public method to unlock canvas
    unlockCanvas() {
        this.setMoveEnabled(true);
    }
    
    // NEW: Method to manually trigger recalc
    recalculateAndCenter() {
        this.calculateAndApplyOptimalZoom();
    }
}


// Global canvasZoom instance
let canvasZoom;

// Create tooltip element (keep your original tooltip system)
const tooltip = document.createElement("div");
tooltip.className = "zoom-tooltip";
document.body.appendChild(tooltip);

// Your original attachTooltip function
function attachTooltip(el, textGetter) {
    let tooltipTimeout;

    function showTooltip() {
        tooltip.textContent =
            typeof textGetter === "function" ? textGetter() : textGetter;

        tooltip.classList.add("show");
        tooltip.style.visibility = "hidden"; // measure safely

        const rect = el.getBoundingClientRect();
        const ttRect = tooltip.getBoundingClientRect();
        const padding = 8;

        let left = rect.left + rect.width / 2;
        let top = rect.top - 8;
        let translateY = "120%";

        // 🔹 If tooltip goes above screen → show below
        if (top < padding) {
            top = rect.bottom + padding;
            translateY = "0";
        }

        // 🔹 Clamp horizontally
        let clampedLeft = left;
        if (left - ttRect.width / 2 < padding) {
            clampedLeft = padding + ttRect.width / 2;
        } else if (left + ttRect.width / 2 > window.innerWidth - padding) {
            clampedLeft = window.innerWidth - padding - ttRect.width / 2;
        }

        tooltip.style.left = clampedLeft + "px";
        tooltip.style.top = top + "px";
        tooltip.style.transform = `translate(-50%, ${translateY})`;
        tooltip.style.visibility = "visible";
    }

    function hideTooltip() {
        tooltip.classList.remove("show");
        if (tooltipTimeout) clearTimeout(tooltipTimeout);
    }

    // Desktop
    el.addEventListener("mouseenter", () => {
        showTooltip();

        if (!isTouchDevice) {
            tooltipTimeout = setTimeout(hideTooltip, 2000);
        }
    });

    el.addEventListener("mouseleave", hideTooltip);

    // Mobile
    if (isTouchDevice) {
        el.addEventListener("touchstart", () => {
            showTooltip();
            setTimeout(hideTooltip, 1000);
        });

        el.addEventListener("touchend", () => {
            setTimeout(hideTooltip, 500);
        });
    }
}

// Initialize zoom after canvas is ready
document.addEventListener('DOMContentLoaded', () => {
    // Initialize zoom functionality
    canvasZoom = new CanvasZoom(canvas);
    addZoomControls();
    
    // Setup resize handler for dynamic adjustment
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            if (canvasZoom) {
                canvasZoom.recalculateZoom();
            }
        }, 250);
    });
    
    // Listen for canvas changes - DYNAMIC ZOOM UPDATE
    if (canvas && canvas.on) {
        // Store previous dimensions for both canvas and container
        let prevCanvasWidth = canvas.width;
        let prevCanvasHeight = canvas.height;
        let prevContainerWidth = canvasZoom.container.offsetWidth;
        let prevContainerHeight = canvasZoom.container.offsetHeight;
      
        
        canvas.on('object:added', () => {
            if (canvasZoom) {
                // Get current dimensions
                const currentCanvasWidth = canvas.width;
                const currentCanvasHeight = canvas.height;
                const currentContainerWidth = canvasZoom.container.offsetWidth;
                const currentContainerHeight = canvasZoom.container.offsetHeight;
                
                // Check if ANY dimension changed
                const canvasChanged = currentCanvasWidth !== prevCanvasWidth || currentCanvasHeight !== prevCanvasHeight;
                const containerChanged = currentContainerWidth !== prevContainerWidth || currentContainerHeight !== prevContainerHeight;
                
                if (canvasChanged || containerChanged) {
                   
                    canvasZoom.recalculateZoom();
                    
                    // Update stored dimensions
                    prevCanvasWidth = currentCanvasWidth;
                    prevCanvasHeight = currentCanvasHeight;
                    prevContainerWidth = currentContainerWidth;
                    prevContainerHeight = currentContainerHeight;
                } 
            }
        });
        
        canvas.on('object:modified', () => {
            // Only update transform, don't recalculate zoom
            if (canvasZoom) {
                canvasZoom.updateTransform();
            }
        });
        
        canvas.on('object:removed', () => {
            if (canvasZoom) {
                // Get current dimensions
                const currentCanvasWidth = canvas.width;
                const currentCanvasHeight = canvas.height;
                const currentContainerWidth = canvasZoom.container.offsetWidth;
                const currentContainerHeight = canvasZoom.container.offsetHeight;
                
                // Check if ANY dimension changed
                const canvasChanged = currentCanvasWidth !== prevCanvasWidth || currentCanvasHeight !== prevCanvasHeight;
                const containerChanged = currentContainerWidth !== prevContainerWidth || currentContainerHeight !== prevContainerHeight;
                
                if (canvasChanged || containerChanged) {
                 
                    
                    canvasZoom.recalculateZoom();
                    
                    // Update stored dimensions
                    prevCanvasWidth = currentCanvasWidth;
                    prevCanvasHeight = currentCanvasHeight;
                    prevContainerWidth = currentContainerWidth;
                    prevContainerHeight = currentContainerHeight;
                } 
            }
        });
        
        canvas.on('object:moving', () => {
            // Update transform in real-time during movement
            if (canvasZoom) {
                canvasZoom.updateTransform();
            }
        });
        
        canvas.on('object:scaling', () => {
            // Update transform in real-time while scaling
            if (canvasZoom) {
                canvasZoom.updateTransform();
            }
        });
        
        // Also monitor container size changes separately (in case container resizes without canvas changes)
        function checkContainerSize() {
            if (!canvasZoom) return;
            
            const currentContainerWidth = canvasZoom.container.offsetWidth;
            const currentContainerHeight = canvasZoom.container.offsetHeight;
            
            if (currentContainerWidth !== prevContainerWidth || currentContainerHeight !== prevContainerHeight) {
               
                
                canvasZoom.recalculateZoom();
                
                prevContainerWidth = currentContainerWidth;
                prevContainerHeight = currentContainerHeight;
            }
        }
        
        // Check container size periodically (as a fallback)
        setInterval(checkContainerSize, 1000);
    }
});

// Attach tooltips to your existing buttons
const centerBtn = document.querySelector("#center-image");
if (centerBtn) {
    attachTooltip(centerBtn, "Center Image (C key)");
    centerBtn.addEventListener('click', () => {
        if (canvasZoom) {
            canvasZoom.centerCanvas();
        }
    });
}

const fitfrontBtn = document.querySelector("#fit-front-image");
if (fitfrontBtn) {
    attachTooltip(fitfrontBtn, "Fit To Placeholder");
    fitfrontBtn.addEventListener('click', () => {
        if (canvasZoom) {
            canvasZoom.fitToContainer(0.8);
        }
    });
}

const fillfrontBtn = document.querySelector("#fill-front-image");
if (fillfrontBtn) {
    attachTooltip(fillfrontBtn, "Fill To Placeholder");
    fillfrontBtn.addEventListener('click', () => {
        if (canvasZoom) {
            canvasZoom.fitToContainer(1);
        }
    });
}

const fillsideBtn = document.querySelector("#fill-side-image");
if (fillsideBtn) {
    attachTooltip(fillsideBtn, "Fill To Side Edge");
    fillsideBtn.addEventListener('click', () => {
        if (canvasZoom) {
            // Custom fill logic for side edge
            canvasZoom.fitToContainer(1.1);
        }
    });
}

const removeImgBtn = document.querySelector(".reset-pdp");
if (removeImgBtn) {
    attachTooltip(removeImgBtn, "Remove Image");
    removeImgBtn.addEventListener('click', () => {
        if (canvasZoom) {
            setTimeout(() => {
                canvasZoom.recalculateZoom();
            }, 100);
        }
    });
}

if (isTouchDevice) {
    document.addEventListener('touchmove', () => {
        document.querySelectorAll('.zoom-tooltip.show').forEach(tooltip => {
            tooltip.classList.remove('show');
        });
    });
}

// Your original addZoomControls function
function addZoomControls() {
    const controls = document.createElement("div");
    controls.style.cssText = `display:flex; gap:5px;`;

    const btnStyle = `
        background:rgba(30,31,37,.5);
        border:1px solid rgba(255,255,255,.1);
        display:flex;
        align-items:center;
        justify-content:center;
        width:32px;
        height:32px;
        cursor:pointer;
    `;

    // ZOOM OUT
    const zoomOutBtn = document.createElement("div");
    zoomOutBtn.innerHTML = `
        <svg width="12" height="2" viewBox="0 0 12 2" fill="none">
            <path d="M0.857143 2H11.1429" stroke="white" stroke-width="2"/>
        </svg>`;
    zoomOutBtn.style.cssText = btnStyle;
    zoomOutBtn.onclick = () => canvasZoom.zoomOut();
    attachTooltip(zoomOutBtn, "Zoom Out (Mouse Wheel)");

    // RESET (now does optimal centered zoom)
    const resetBtn = document.createElement("div");
    resetBtn.textContent = "Reset";
    resetBtn.style.cssText = btnStyle + "padding:0 10px;width:auto;";
    resetBtn.onclick = () => canvasZoom.resetZoom();
    attachTooltip(resetBtn, "Fit & Center Canvas (F)");

    // ZOOM IN
    const zoomInBtn = document.createElement("div");
    zoomInBtn.innerHTML = `
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M6 0V12M0 6H12" stroke="white" stroke-width="2"/>
        </svg>`;
    zoomInBtn.style.cssText = btnStyle;
    zoomInBtn.onclick = () => canvasZoom.zoomIn();
    attachTooltip(zoomInBtn, "Zoom In (Mouse Wheel)");

    // MOVE TOGGLE
    const moveBtn = document.createElement("div");
    moveBtn.innerHTML = `
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
            <path d="M8.09585 12.2506V7.27935M15.8834 11.3545V14.4895M10.6917 12.2663V5.03543M13.2875 12.3991V3.7425"
                stroke="white" stroke-width="1.25" stroke-linecap="round"/>
        </svg>`;
    moveBtn.style.cssText = btnStyle;
    moveBtn.onclick = () => {
        canvasZoom.toggleMove();
        canvasZoom.updateMoveIcon();
    };
    
    // Update tooltip text based on device
    const getMoveTooltipText = () => {
        const isEnabled = canvasZoom.moveEnabled;
        if (isEnabled) {
            return "Disable canvas move " + (isTouchDevice ? "(Long-press canvas)" : "(Right-click/M key)");
        } else {
            return "Enable canvas move " + (isTouchDevice ? "(Long-press canvas)" : "(Right-click/M key)");
        }
    };
    
    attachTooltip(moveBtn, getMoveTooltipText);

    canvasZoom.moveIconBtn = moveBtn;

    controls.append(zoomOutBtn, resetBtn, zoomInBtn, moveBtn);
    document.querySelector(".canvas-zoom-wrap").appendChild(controls);

    canvasZoom.updateMoveIcon();
}

// Global functions for external access
window.recalculateCanvasZoom = function() {
    if (canvasZoom) {
        canvasZoom.recalculateZoom();
    }
};

window.centerCanvas = function() {
    if (canvasZoom) {
        canvasZoom.centerCanvas();
    }
};

window.fitCanvasToContainer = function(padding = 0.9) {
    if (canvasZoom) {
        canvasZoom.fitToContainer(padding);
    }
};

window.getCanvasZoom = function() {
    return canvasZoom;
};

