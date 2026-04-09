const upload = document.getElementById("upload");
        const fWidthInput = document.getElementById("fWidth");
        const fHeightInput = document.getElementById("fHeight");
        const ratioInput = document.getElementById("ratio");
        const scaleInput = document.getElementById("scale");
        const leftOffsetInput = document.getElementById("leftOffset");
        const topOffsetInput = document.getElementById("topOffset");
        const imgWidthInput = document.getElementById("imgWidth");
        const imgHeightInput = document.getElementById("imgHeight");
        const canvasImgWidthInput = document.getElementById("canvasImgWidth");
        const canvasImgHeightInput = document.getElementById("canvasImgHeight");
        const lockAspect = document.getElementById("lockAspect");
        const useCustomSize = document.getElementById("useCustomSize");
        const frameColorInput = document.getElementById("frameColor");
        const container = document.getElementById("threeContainer");

        let imageURL = null;
        let loadedImg = null;
        let origW = 0;
        let origH = 0;
        let aspect = 1;
        let lastTouchDistance = null;
        let isPinching = false;
        let currentMesh = null;

        const MM_PER_INCH = 25.4;
        const PX_PER_INCH = 96;

        function mmToPx(mm) {
            return (mm / MM_PER_INCH) * PX_PER_INCH;
        }

        function pxToSceneUnits(px, ratio) {
            return px / ratio / 100;
        }

        const FRAME_SPEC = Object.freeze({
            frontFacePx: mmToPx(20),
            sideDepthPx: mmToPx(20),
            posterInsetPx: mmToPx(4),
            backBorderPx: mmToPx(14),
            backInsetPx: mmToPx(9)
        });

        const POSTER_SPEC = Object.freeze({
            boardThicknessPx: mmToPx(1.6),
            posterThicknessPx: mmToPx(0.6),
            glazeGapPx: mmToPx(0.35)
        });

        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0xffffff);

        const camera = new THREE.PerspectiveCamera(48, container.clientWidth / container.clientHeight, 0.1, 2000);
        camera.position.set(4.2, 2.4, 8.6);
        camera.lookAt(0, 0, 0);

        const renderer = new THREE.WebGLRenderer({ antialias: true });
        renderer.setSize(container.clientWidth, container.clientHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        renderer.outputColorSpace = THREE.SRGBColorSpace;
        renderer.toneMapping = THREE.ACESFilmicToneMapping;
        renderer.toneMappingExposure = 1.05;
        container.appendChild(renderer.domElement);

        scene.add(new THREE.AmbientLight(0xffffff, 1.65));

        const keyLight = new THREE.DirectionalLight(0xffffff, 1.35);
        keyLight.position.set(10, 15, 12);
        scene.add(keyLight);

        const frontLight = new THREE.DirectionalLight(0xffffff, 0.85);
        frontLight.position.set(0, 2, 10);
        scene.add(frontLight);

        const rimLight = new THREE.DirectionalLight(0xffffff, 0.75);
        rimLight.position.set(-8, 6, -10);
        scene.add(rimLight);

        const wrapGroup = new THREE.Group();
        scene.add(wrapGroup);

        container.addEventListener("touchstart", (e) => {
            if (e.touches.length === 2) {
                e.preventDefault();
                isPinching = true;
                const dx = e.touches[0].clientX - e.touches[1].clientX;
                const dy = e.touches[0].clientY - e.touches[1].clientY;
                lastTouchDistance = Math.hypot(dx, dy);
            }
        }, { passive: false });

        container.addEventListener("touchmove", (e) => {
            if (e.touches.length === 2 && isPinching) {
                e.preventDefault();
                const dx = e.touches[0].clientX - e.touches[1].clientX;
                const dy = e.touches[0].clientY - e.touches[1].clientY;
                const dist = Math.hypot(dx, dy);

                if (lastTouchDistance !== null) {
                    const delta = lastTouchDistance - dist;
                    camera.fov = THREE.MathUtils.clamp(camera.fov + delta * 0.08, 20, 110);
                    camera.updateProjectionMatrix();
                }

                lastTouchDistance = dist;
            }
        }, { passive: false });

        container.addEventListener("touchend", (e) => {
            if (e.touches.length < 2) {
                isPinching = false;
                lastTouchDistance = null;
            }
        });

        function makeFaceTexture(img, sx, sy, sw, sh, scaleX, scaleY) {
            const maxSize = 1400;
            let ix = Math.round(sx * scaleX);
            let iy = Math.round(sy * scaleY);
            let iw = Math.round(sw * scaleX);
            let ih = Math.round(sh * scaleY);
            if (iw <= 0 || ih <= 0) return new THREE.Texture();

            const sourceAspect = iw / ih;
            let texSizeW;
            let texSizeH;

            if (sourceAspect > 1) {
                texSizeW = maxSize;
                texSizeH = Math.max(1, Math.round(maxSize / sourceAspect));
            } else {
                texSizeH = maxSize;
                texSizeW = Math.max(1, Math.round(maxSize * sourceAspect));
            }

            const cvs = document.createElement("canvas");
            cvs.width = texSizeW;
            cvs.height = texSizeH;

            const ctx = cvs.getContext("2d");
            ctx.imageSmoothingQuality = "high";
            ctx.fillStyle = "white";
            ctx.fillRect(0, 0, texSizeW, texSizeH);

            let srcX = ix;
            let srcY = iy;
            let srcW = iw;
            let srcH = ih;
            const clipLeft = Math.max(0, -srcX);
            const clipTop = Math.max(0, -srcY);
            const clipRight = Math.max(0, srcX + srcW - img.width);
            const clipBottom = Math.max(0, srcY + srcH - img.height);
            const destX = (clipLeft / iw) * texSizeW;
            const destY = (clipTop / ih) * texSizeH;
            const destW = texSizeW - ((clipLeft + clipRight) / iw) * texSizeW;
            const destH = texSizeH - ((clipTop + clipBottom) / ih) * texSizeH;

            srcX += clipLeft;
            srcY += clipTop;
            srcW -= clipLeft + clipRight;
            srcH -= clipTop + clipBottom;

            if (srcW > 0 && srcH > 0 && destW > 0 && destH > 0) {
                ctx.drawImage(img, srcX, srcY, srcW, srcH, destX, destY, destW, destH);
            }

            const tex = new THREE.CanvasTexture(cvs);
            tex.wrapS = tex.wrapT = THREE.ClampToEdgeWrapping;
            tex.minFilter = THREE.LinearFilter;
            tex.magFilter = THREE.LinearFilter;
            tex.colorSpace = THREE.SRGBColorSpace;
            tex.anisotropy = renderer.capabilities.getMaxAnisotropy();
            tex.needsUpdate = true;
            return tex;
        }

        function disposeMaterial(material) {
            if (!material) return;
            if (material.map) material.map.dispose();
            material.dispose();
        }

        function disposeWrapGroup(group) {
            const materials = new Set();

            group.traverse((child) => {
                if (!child.isMesh) return;
                if (child.geometry) child.geometry.dispose();

                if (Array.isArray(child.material)) {
                    child.material.forEach((material) => materials.add(material));
                } else if (child.material) {
                    materials.add(child.material);
                }
            });

            materials.forEach(disposeMaterial);
        }

        function createFrameRingGeometry(outerWidth, outerHeight, innerWidth, innerHeight, depth) {
            const safeDepth = Math.max(0.001, depth);
            const safeOuterWidth = Math.max(0.01, outerWidth);
            const safeOuterHeight = Math.max(0.01, outerHeight);
            const safeInnerWidth = Math.max(0.001, Math.min(innerWidth, safeOuterWidth - 0.002));
            const safeInnerHeight = Math.max(0.001, Math.min(innerHeight, safeOuterHeight - 0.002));
            const holeX = (safeOuterWidth - safeInnerWidth) / 2;
            const holeY = (safeOuterHeight - safeInnerHeight) / 2;

            const shape = new THREE.Shape();
            shape.moveTo(0, 0);
            shape.lineTo(safeOuterWidth, 0);
            shape.lineTo(safeOuterWidth, safeOuterHeight);
            shape.lineTo(0, safeOuterHeight);
            shape.lineTo(0, 0);

            const hole = new THREE.Path();
            hole.moveTo(holeX, holeY);
            hole.lineTo(holeX, holeY + safeInnerHeight);
            hole.lineTo(holeX + safeInnerWidth, holeY + safeInnerHeight);
            hole.lineTo(holeX + safeInnerWidth, holeY);
            hole.lineTo(holeX, holeY);
            shape.holes.push(hole);

            const geometry = new THREE.ExtrudeGeometry(shape, {
                depth: safeDepth,
                bevelEnabled: false,
                curveSegments: 1,
                steps: 1
            });

            geometry.translate(-safeOuterWidth / 2, -safeOuterHeight / 2, -safeDepth / 2);
            geometry.computeVertexNormals();
            return geometry;
        }

        function addRingSection(group, outerWidth, outerHeight, innerWidth, innerHeight, depth, zCenter, material) {
            const mesh = new THREE.Mesh(
                createFrameRingGeometry(outerWidth, outerHeight, innerWidth, innerHeight, depth),
                material
            );
            mesh.position.z = zCenter;
            group.add(mesh);
            return mesh;
        }

        function addOuterFrame(group, outerWidth, outerHeight, ratio, frameColor) {
            const faceWidth = pxToSceneUnits(FRAME_SPEC.frontFacePx, ratio);
            const profileDepth = pxToSceneUnits(FRAME_SPEC.sideDepthPx, ratio);
            const posterInset = Math.min(pxToSceneUnits(FRAME_SPEC.posterInsetPx, ratio), profileDepth - 0.001);
            const backBorderWidth = pxToSceneUnits(FRAME_SPEC.backBorderPx, ratio);
            const backInsetDepth = Math.min(pxToSceneUnits(FRAME_SPEC.backInsetPx, ratio), profileDepth - 0.001);

            const openingWidth = Math.max(0.05, outerWidth - faceWidth * 2);
            const openingHeight = Math.max(0.05, outerHeight - faceWidth * 2);
            const backOpeningWidth = Math.max(openingWidth + 0.002, outerWidth - backBorderWidth * 2);
            const backOpeningHeight = Math.max(openingHeight + 0.002, outerHeight - backBorderWidth * 2);
            const frontSectionDepth = Math.max(0.001, profileDepth - backInsetDepth);
            const cavityDepth = Math.max(0.001, profileDepth - posterInset - backInsetDepth);

            const frameBaseColor = new THREE.Color(frameColor || "#171717");
            const rabbetColor = frameBaseColor.clone().lerp(new THREE.Color(0xb9ad9a), 0.2);
            const cavityColor = frameBaseColor.clone().multiplyScalar(0.78);

            const frameMaterial = new THREE.MeshPhysicalMaterial({
                color: frameBaseColor,
                roughness: 0.38,
                metalness: 0.12,
                clearcoat: 1,
                clearcoatRoughness: 0.14
            });

            const rabbetMaterial = new THREE.MeshStandardMaterial({
                color: rabbetColor,
                roughness: 0.72,
                metalness: 0.04
            });

            const cavityMaterial = new THREE.MeshStandardMaterial({
                color: cavityColor,
                roughness: 0.82,
                metalness: 0.04,
                side: THREE.DoubleSide
            });

            addRingSection(
                group,
                outerWidth,
                outerHeight,
                openingWidth,
                openingHeight,
                frontSectionDepth,
                backInsetDepth / 2,
                frameMaterial
            );

            addRingSection(
                group,
                outerWidth,
                outerHeight,
                backOpeningWidth,
                backOpeningHeight,
                backInsetDepth,
                -profileDepth / 2 + backInsetDepth / 2,
                rabbetMaterial
            );

            addRingSection(
                group,
                backOpeningWidth,
                backOpeningHeight,
                openingWidth,
                openingHeight,
                cavityDepth,
                -profileDepth / 2 + backInsetDepth + cavityDepth / 2,
                cavityMaterial
            );

            return {
                openingWidth,
                openingHeight,
                backOpeningWidth,
                backOpeningHeight,
                profileDepth,
                posterInset,
                backInsetDepth,
                frontFaceZ: profileDepth / 2
            };
        }

        function updateThreePreview() {
            if (!imageURL || !loadedImg || loadedImg.naturalWidth === 0) return;

            disposeWrapGroup(wrapGroup);
            wrapGroup.clear();
            currentMesh = null;

            const ratio = Math.max(0.1, +ratioInput.value || 1);
            const outerWidthPx = Math.max(120, (+fWidthInput.value || 900) / ratio);
            const outerHeightPx = Math.max(120, (+fHeightInput.value || 600) / ratio);
            const frontFacePx = FRAME_SPEC.frontFacePx / ratio;
            const openingWidthPx = Math.max(10, outerWidthPx - frontFacePx * 2);
            const openingHeightPx = Math.max(10, outerHeightPx - frontFacePx * 2);

            let effW;
            let effH;

            if (useCustomSize.checked) {
                effW = +canvasImgWidthInput.value || origW;
                effH = +canvasImgHeightInput.value || origH;
            } else {
                const fitScale = Math.max(openingWidthPx / origW, openingHeightPx / origH);
                effW = origW * fitScale * (+scaleInput.value || 1);
                effH = origH * fitScale * (+scaleInput.value || 1);
            }

            if (effW < 10 || effH < 10 || origW === 0 || origH === 0) return;

            const offsetX = (+leftOffsetInput.value || 0) / ratio;
            const offsetY = (+topOffsetInput.value || 0) / ratio;
            const scaleX = origW / effW;
            const scaleY = origH / effH;

            const texFront = makeFaceTexture(
                loadedImg,
                offsetX,
                offsetY,
                openingWidthPx,
                openingHeightPx,
                scaleX,
                scaleY
            );

            const frameDims = addOuterFrame(
                wrapGroup,
                outerWidthPx / 100,
                outerHeightPx / 100,
                ratio,
                frameColorInput.value
            );

            const posterThickness = Math.max(0.0015, pxToSceneUnits(POSTER_SPEC.posterThicknessPx, ratio));
            const boardThickness = Math.max(0.002, pxToSceneUnits(POSTER_SPEC.boardThicknessPx, ratio));
            const glazeGap = Math.max(0.0006, pxToSceneUnits(POSTER_SPEC.glazeGapPx, ratio));

            const posterFrontZ = frameDims.frontFaceZ - frameDims.posterInset;
            const posterCenterZ = posterFrontZ - posterThickness / 2;

            const posterFrontMaterial = new THREE.MeshPhysicalMaterial({
                map: texFront,
                roughness: 0.28,
                metalness: 0,
                clearcoat: 1,
                clearcoatRoughness: 0.03
            });

            const posterEdgeMaterial = new THREE.MeshStandardMaterial({
                color: 0xf3efe5,
                roughness: 0.9,
                metalness: 0
            });

            const posterBackMaterial = new THREE.MeshStandardMaterial({
                color: 0xf1ece2,
                roughness: 0.88,
                metalness: 0
            });

            currentMesh = new THREE.Mesh(
                new THREE.BoxGeometry(frameDims.openingWidth, frameDims.openingHeight, posterThickness),
                [
                    posterEdgeMaterial,
                    posterEdgeMaterial,
                    posterEdgeMaterial,
                    posterEdgeMaterial,
                    posterFrontMaterial,
                    posterBackMaterial
                ]
            );
            currentMesh.position.set(0, 0, posterCenterZ);
            wrapGroup.add(currentMesh);

            const glaze = new THREE.Mesh(
                new THREE.PlaneGeometry(frameDims.openingWidth, frameDims.openingHeight),
                new THREE.MeshPhysicalMaterial({
                    color: 0xffffff,
                    transparent: true,
                    opacity: 0.14,
                    roughness: 0.05,
                    metalness: 0,
                    clearcoat: 1,
                    clearcoatRoughness: 0.02,
                    side: THREE.DoubleSide
                })
            );
            glaze.position.z = Math.min(frameDims.frontFaceZ - 0.0008, posterFrontZ + glazeGap);
            wrapGroup.add(glaze);

            const backing = new THREE.Mesh(
                new THREE.BoxGeometry(frameDims.backOpeningWidth, frameDims.backOpeningHeight, boardThickness),
                new THREE.MeshStandardMaterial({
                    color: 0xf4f4ef,
                    roughness: 0.94,
                    metalness: 0.01
                })
            );
            backing.position.z = -frameDims.profileDepth / 2 + frameDims.backInsetDepth - boardThickness / 2;
            wrapGroup.add(backing);

            wrapGroup.rotation.y = -0.58;
            wrapGroup.rotation.x = 0.16;
        }

        upload.addEventListener("change", (e) => {
            const file = e.target.files[0];
            if (!file) return;

            if (imageURL) URL.revokeObjectURL(imageURL);
            imageURL = URL.createObjectURL(file);

            const img = new Image();
            img.onload = () => {
                origW = img.naturalWidth;
                origH = img.naturalHeight;
                aspect = origH / origW || 1;
                imgWidthInput.value = origW;
                imgHeightInput.value = origH;
                canvasImgWidthInput.value = origW;
                canvasImgHeightInput.value = origH;
                loadedImg = img;
                updateThreePreview();
            };
            img.src = imageURL;
        });

        function syncAspectWidth() {
            if (lockAspect.checked) imgHeightInput.value = Math.round(imgWidthInput.value * aspect);
        }

        function syncAspectHeight() {
            if (lockAspect.checked) imgWidthInput.value = Math.round(imgHeightInput.value / aspect);
        }

        function syncCanvasWidth() {
            if (lockAspect.checked) canvasImgHeightInput.value = Math.round(canvasImgWidthInput.value * aspect);
            updateThreePreview();
        }

        function syncCanvasHeight() {
            if (lockAspect.checked) canvasImgWidthInput.value = Math.round(canvasImgHeightInput.value / aspect);
            updateThreePreview();
        }

        imgWidthInput.addEventListener("input", syncAspectWidth);
        imgHeightInput.addEventListener("input", syncAspectHeight);
        canvasImgWidthInput.addEventListener("input", syncCanvasWidth);
        canvasImgHeightInput.addEventListener("input", syncCanvasHeight);

        [
            fWidthInput,
            fHeightInput,
            ratioInput,
            scaleInput,
            leftOffsetInput,
            topOffsetInput,
            useCustomSize,
            frameColorInput
        ].forEach((el) => el.addEventListener("input", updateThreePreview));

        let isDragging = false;
        const previousMouse = { x: 0, y: 0 };

        container.addEventListener("pointerdown", (e) => {
            isDragging = true;
            previousMouse.x = e.clientX;
            previousMouse.y = e.clientY;
            container.style.cursor = "grabbing";
        });

        window.addEventListener("pointerup", () => {
            isDragging = false;
            container.style.cursor = "grab";
        });

        window.addEventListener("pointermove", (e) => {
            if (!isDragging || isPinching) return;

            wrapGroup.rotation.y += (e.clientX - previousMouse.x) * 0.004;
            wrapGroup.rotation.x += (e.clientY - previousMouse.y) * 0.004;

            previousMouse.x = e.clientX;
            previousMouse.y = e.clientY;
        });

        container.addEventListener("selectstart", (e) => e.preventDefault());
        container.addEventListener("wheel", (e) => {
            e.preventDefault();
            camera.fov = THREE.MathUtils.clamp(camera.fov + e.deltaY * 0.06, 20, 110);
            camera.updateProjectionMatrix();
        }, { passive: false });

        window.addEventListener("resize", () => {
            camera.aspect = container.clientWidth / container.clientHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(container.clientWidth, container.clientHeight);
        });

        function animate() {
            requestAnimationFrame(animate);
            renderer.render(scene, camera);
        }

        animate();
