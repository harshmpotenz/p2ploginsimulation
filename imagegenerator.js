"use strict";

const crypto = require("crypto");
const sharp = require("sharp");
const { S3Client, PutObjectCommand } = require("@aws-sdk/client-s3");

function pickFirstValue(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

function toNonNegativeInteger(value, fieldName) {
  const numericValue = Number(value);

  if (!Number.isFinite(numericValue) || numericValue < 0) {
    throw new Error(`${fieldName} must be a non-negative number.`);
  }

  return Math.round(numericValue);
}

function toPositiveInteger(value, fieldName) {
  const numericValue = Number(value);

  if (!Number.isFinite(numericValue) || numericValue <= 0) {
    throw new Error(`${fieldName} must be a positive number.`);
  }

  return Math.round(numericValue);
}

function toBoolean(value, fallback = true) {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    return value !== 0;
  }

  if (typeof value === "string") {
    const normalized = value.trim().toLowerCase();

    if (["true", "1", "yes", "enabled", "on"].includes(normalized)) {
      return true;
    }

    if (["false", "0", "no", "disabled", "off"].includes(normalized)) {
      return false;
    }
  }

  return fallback;
}

function decodeDataUri(dataUri) {
  const match = /^data:(.+);base64,(.+)$/i.exec(dataUri);

  if (!match) {
    throw new Error("Unsupported data URI for originalImage.");
  }

  return Buffer.from(match[2], "base64");
}

async function fetchRemoteBuffer(url) {
  const fetchImpl = typeof fetch === "function"
    ? fetch
    : (await import("node-fetch")).default;

  const response = await fetchImpl(url);

  if (!response.ok) {
    throw new Error(`Failed to download originalImage: ${response.status} ${response.statusText}`);
  }

  const arrayBuffer = await response.arrayBuffer();
  return Buffer.from(arrayBuffer);
}

async function resolveOriginalImageBuffer(originalImage) {
  if (!originalImage) {
    throw new Error("originalImage is required.");
  }

  if (Buffer.isBuffer(originalImage)) {
    return originalImage;
  }

  if (originalImage instanceof Uint8Array) {
    return Buffer.from(originalImage);
  }

  if (typeof originalImage === "string") {
    if (originalImage.startsWith("data:")) {
      return decodeDataUri(originalImage);
    }

    if (originalImage.startsWith("http://") || originalImage.startsWith("https://")) {
      return fetchRemoteBuffer(originalImage);
    }

    throw new Error("originalImage must be a Buffer, data URI, or absolute URL.");
  }

  if (typeof originalImage === "object") {
    const nestedSource = pickFirstValue(
      originalImage.buffer,
      originalImage.data,
      originalImage.url,
      originalImage.imageUrl,
      originalImage.src,
      originalImage.originalImage
    );

    if (nestedSource) {
      return resolveOriginalImageBuffer(nestedSource);
    }
  }

  throw new Error("Unsupported originalImage payload.");
}

function normalizeCanvasGeometry(payload) {
  const imageLeft = toNonNegativeInteger(
    pickFirstValue(payload.left, payload.imageLeft, payload.offsetLeft),
    "left"
  );
  const imageTop = toNonNegativeInteger(
    pickFirstValue(payload.top, payload.imageTop, payload.offsetTop),
    "top"
  );
  const imageWidth = toPositiveInteger(
    pickFirstValue(payload.width, payload.imageWidth, payload.renderedImageWidth),
    "width"
  );
  const imageHeight = toPositiveInteger(
    pickFirstValue(payload.height, payload.imageHeight, payload.renderedImageHeight),
    "height"
  );

  const rightInsetInput = pickFirstValue(payload.rightInset, payload.rightMargin);
  const bottomInsetInput = pickFirstValue(payload.bottomInset, payload.bottomMargin);
  const canvasWidthInput = pickFirstValue(payload.canvasWidth, payload.outputWidth, payload.wrapWidth);
  const canvasHeightInput = pickFirstValue(payload.canvasHeight, payload.outputHeight, payload.wrapHeight);

  const canvasWidth = canvasWidthInput !== undefined && canvasWidthInput !== null && canvasWidthInput !== ""
    ? toPositiveInteger(canvasWidthInput, "canvasWidth")
    : imageLeft + imageWidth + (rightInsetInput !== undefined ? toNonNegativeInteger(rightInsetInput, "rightInset") : imageLeft);

  const canvasHeight = canvasHeightInput !== undefined && canvasHeightInput !== null && canvasHeightInput !== ""
    ? toPositiveInteger(canvasHeightInput, "canvasHeight")
    : imageTop + imageHeight + (bottomInsetInput !== undefined ? toNonNegativeInteger(bottomInsetInput, "bottomInset") : imageTop);

  const rightInset = Math.max(0, canvasWidth - imageLeft - imageWidth);
  const bottomInset = Math.max(0, canvasHeight - imageTop - imageHeight);

  return {
    canvasWidth,
    canvasHeight,
    imageLeft,
    imageTop,
    imageWidth,
    imageHeight,
    leftInset: imageLeft,
    topInset: imageTop,
    rightInset,
    bottomInset
  };
}

async function buildPlacedImageBuffer(originalBuffer, imageWidth, imageHeight) {
  return sharp(originalBuffer)
    .rotate()
    .resize(imageWidth, imageHeight, { fit: "fill" })
    .jpeg({ quality: 92, mozjpeg: true })
    .toBuffer();
}

async function createMirroredRegion(placedImageBuffer, extractRegion, resizeRegion, options = {}) {
  if (resizeRegion.width <= 0 || resizeRegion.height <= 0) {
    return null;
  }

  let pipeline = sharp(placedImageBuffer).extract(extractRegion);

  if (options.flip) {
    pipeline = pipeline.flip();
  }

  if (options.flop) {
    pipeline = pipeline.flop();
  }

  return pipeline
    .resize(resizeRegion.width, resizeRegion.height, { fit: "fill" })
    .png()
    .toBuffer();
}

function buildCreateBackground(color) {
  return color || "#1a0505";
}

async function buildMirrorWrapBuffer(payload = {}) {
  const originalImage = pickFirstValue(
    payload.originalImage,
    payload.image,
    payload.imageUrl,
    payload.source
  );
  const originalBuffer = await resolveOriginalImageBuffer(originalImage);
  const geometry = normalizeCanvasGeometry(payload);
  const printOnSideEnabled = toBoolean(
    pickFirstValue(payload.printOnSideEnabled, payload.printOnSide, payload.isPrintOnSideEnabled),
    true
  );
  const sideFillColor = pickFirstValue(payload.sideFillColor, payload.backgroundColor, "#ffffff");
  const placedImageBuffer = await buildPlacedImageBuffer(
    originalBuffer,
    geometry.imageWidth,
    geometry.imageHeight
  );

  const composites = [];

  if (printOnSideEnabled) {
    if (geometry.topInset > 0) {
      const sampleHeight = Math.max(1, Math.min(geometry.topInset, geometry.imageHeight));
      const topBuffer = await createMirroredRegion(
        placedImageBuffer,
        { left: 0, top: 0, width: geometry.imageWidth, height: sampleHeight },
        { width: geometry.imageWidth, height: geometry.topInset },
        { flip: true }
      );

      composites.push({ input: topBuffer, left: geometry.imageLeft, top: 0 });
    }

    if (geometry.bottomInset > 0) {
      const sampleHeight = Math.max(1, Math.min(geometry.bottomInset, geometry.imageHeight));
      const bottomBuffer = await createMirroredRegion(
        placedImageBuffer,
        {
          left: 0,
          top: Math.max(0, geometry.imageHeight - sampleHeight),
          width: geometry.imageWidth,
          height: sampleHeight
        },
        { width: geometry.imageWidth, height: geometry.bottomInset },
        { flip: true }
      );

      composites.push({
        input: bottomBuffer,
        left: geometry.imageLeft,
        top: geometry.imageTop + geometry.imageHeight
      });
    }

    if (geometry.leftInset > 0) {
      const sampleWidth = Math.max(1, Math.min(geometry.leftInset, geometry.imageWidth));
      const leftBuffer = await createMirroredRegion(
        placedImageBuffer,
        { left: 0, top: 0, width: sampleWidth, height: geometry.imageHeight },
        { width: geometry.leftInset, height: geometry.imageHeight },
        { flop: true }
      );

      composites.push({ input: leftBuffer, left: 0, top: geometry.imageTop });
    }

    if (geometry.rightInset > 0) {
      const sampleWidth = Math.max(1, Math.min(geometry.rightInset, geometry.imageWidth));
      const rightBuffer = await createMirroredRegion(
        placedImageBuffer,
        {
          left: Math.max(0, geometry.imageWidth - sampleWidth),
          top: 0,
          width: sampleWidth,
          height: geometry.imageHeight
        },
        { width: geometry.rightInset, height: geometry.imageHeight },
        { flop: true }
      );

      composites.push({
        input: rightBuffer,
        left: geometry.imageLeft + geometry.imageWidth,
        top: geometry.imageTop
      });
    }

    if (geometry.leftInset > 0 && geometry.topInset > 0) {
      const topLeftBuffer = await createMirroredRegion(
        placedImageBuffer,
        {
          left: 0,
          top: 0,
          width: Math.max(1, Math.min(geometry.leftInset, geometry.imageWidth)),
          height: Math.max(1, Math.min(geometry.topInset, geometry.imageHeight))
        },
        { width: geometry.leftInset, height: geometry.topInset },
        { flip: true, flop: true }
      );

      composites.push({ input: topLeftBuffer, left: 0, top: 0 });
    }

    if (geometry.rightInset > 0 && geometry.topInset > 0) {
      const topRightSampleWidth = Math.max(1, Math.min(geometry.rightInset, geometry.imageWidth));
      const topRightSampleHeight = Math.max(1, Math.min(geometry.topInset, geometry.imageHeight));
      const topRightBuffer = await createMirroredRegion(
        placedImageBuffer,
        {
          left: Math.max(0, geometry.imageWidth - topRightSampleWidth),
          top: 0,
          width: topRightSampleWidth,
          height: topRightSampleHeight
        },
        { width: geometry.rightInset, height: geometry.topInset },
        { flip: true, flop: true }
      );

      composites.push({
        input: topRightBuffer,
        left: geometry.imageLeft + geometry.imageWidth,
        top: 0
      });
    }

    if (geometry.leftInset > 0 && geometry.bottomInset > 0) {
      const bottomLeftSampleWidth = Math.max(1, Math.min(geometry.leftInset, geometry.imageWidth));
      const bottomLeftSampleHeight = Math.max(1, Math.min(geometry.bottomInset, geometry.imageHeight));
      const bottomLeftBuffer = await createMirroredRegion(
        placedImageBuffer,
        {
          left: 0,
          top: Math.max(0, geometry.imageHeight - bottomLeftSampleHeight),
          width: bottomLeftSampleWidth,
          height: bottomLeftSampleHeight
        },
        { width: geometry.leftInset, height: geometry.bottomInset },
        { flip: true, flop: true }
      );

      composites.push({
        input: bottomLeftBuffer,
        left: 0,
        top: geometry.imageTop + geometry.imageHeight
      });
    }

    if (geometry.rightInset > 0 && geometry.bottomInset > 0) {
      const bottomRightSampleWidth = Math.max(1, Math.min(geometry.rightInset, geometry.imageWidth));
      const bottomRightSampleHeight = Math.max(1, Math.min(geometry.bottomInset, geometry.imageHeight));
      const bottomRightBuffer = await createMirroredRegion(
        placedImageBuffer,
        {
          left: Math.max(0, geometry.imageWidth - bottomRightSampleWidth),
          top: Math.max(0, geometry.imageHeight - bottomRightSampleHeight),
          width: bottomRightSampleWidth,
          height: bottomRightSampleHeight
        },
        { width: geometry.rightInset, height: geometry.bottomInset },
        { flip: true, flop: true }
      );

      composites.push({
        input: bottomRightBuffer,
        left: geometry.imageLeft + geometry.imageWidth,
        top: geometry.imageTop + geometry.imageHeight
      });
    }
  }

  composites.push({
    input: placedImageBuffer,
    left: geometry.imageLeft,
    top: geometry.imageTop
  });

  const outputBuffer = await sharp({
    create: {
      width: geometry.canvasWidth,
      height: geometry.canvasHeight,
      channels: 4,
      background: buildCreateBackground(sideFillColor)
    }
  })
    .composite(composites)
    .jpeg({ quality: 92, mozjpeg: true })
    .toBuffer();

  return {
    buffer: outputBuffer,
    contentType: "image/jpeg",
    printOnSideEnabled,
    ...geometry
  };
}

function getAwsRegion(options = {}) {
  return pickFirstValue(
    options.region,
    process.env.AWS_REGION,
    process.env.AWS_DEFAULT_REGION,
    process.env.S3_REGION
  );
}

function getAwsBucket(options = {}) {
  return pickFirstValue(
    options.bucket,
    process.env.AWS_S3_BUCKET,
    process.env.S3_BUCKET,
    process.env.AWS_BUCKET_NAME
  );
}

function buildS3Client(options = {}) {
  const region = getAwsRegion(options);

  if (!region) {
    throw new Error("Missing AWS region. Pass region or set AWS_REGION.");
  }

  const accessKeyId = pickFirstValue(options.accessKeyId, process.env.AWS_ACCESS_KEY_ID);
  const secretAccessKey = pickFirstValue(options.secretAccessKey, process.env.AWS_SECRET_ACCESS_KEY);
  const sessionToken = pickFirstValue(options.sessionToken, process.env.AWS_SESSION_TOKEN);
  const clientOptions = { region };

  if (accessKeyId && secretAccessKey) {
    clientOptions.credentials = {
      accessKeyId,
      secretAccessKey,
      sessionToken
    };
  }

  return new S3Client(clientOptions);
}

function buildObjectKey(options = {}) {
  const rawPrefix = pickFirstValue(options.keyPrefix, options.s3KeyPrefix, "mirror-wrap");
  const prefix = String(rawPrefix).replace(/^\/+|\/+$/g, "");
  const defaultFileName = `${Date.now()}-${crypto.randomUUID()}.jpg`;
  const fileName = pickFirstValue(options.fileName, defaultFileName);

  return `${prefix}/${fileName}`;
}

function buildPublicUrl({ bucket, region, key, publicBaseUrl }) {
  if (publicBaseUrl) {
    return `${String(publicBaseUrl).replace(/\/+$/, "")}/${key}`;
  }

  return `https://${bucket}.s3.${region}.amazonaws.com/${key}`;
}

async function uploadBufferToS3(buffer, options = {}) {
  const bucket = getAwsBucket(options);
  const region = getAwsRegion(options);

  if (!bucket) {
    throw new Error("Missing S3 bucket. Pass bucket or set AWS_S3_BUCKET.");
  }

  if (!region) {
    throw new Error("Missing AWS region. Pass region or set AWS_REGION.");
  }

  const key = pickFirstValue(options.key, buildObjectKey(options));
  const client = buildS3Client(options);

  await client.send(new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: buffer,
    ContentType: pickFirstValue(options.contentType, "image/jpeg"),
    CacheControl: pickFirstValue(options.cacheControl, "public, max-age=31536000, immutable")
  }));

  const publicBaseUrl = pickFirstValue(
    options.publicBaseUrl,
    process.env.AWS_CLOUDFRONT_BASE_URL,
    process.env.CLOUDFRONT_BASE_URL,
    process.env.S3_PUBLIC_BASE_URL
  );

  return {
    bucket,
    region,
    key,
    url: buildPublicUrl({ bucket, region, key, publicBaseUrl })
  };
}

async function generateMirrorWrapImage(payload = {}) {
  const builtImage = await buildMirrorWrapBuffer(payload);
  const uploadResult = await uploadBufferToS3(builtImage.buffer, {
    bucket: payload.bucket,
    region: payload.region,
    key: payload.key,
    keyPrefix: payload.keyPrefix,
    s3KeyPrefix: payload.s3KeyPrefix,
    fileName: payload.fileName,
    contentType: builtImage.contentType,
    cacheControl: payload.cacheControl,
    publicBaseUrl: payload.publicBaseUrl,
    accessKeyId: payload.accessKeyId,
    secretAccessKey: payload.secretAccessKey,
    sessionToken: payload.sessionToken
  });

  return {
    url: uploadResult.url,
    key: uploadResult.key,
    bucket: uploadResult.bucket,
    region: uploadResult.region,
    canvasWidth: builtImage.canvasWidth,
    canvasHeight: builtImage.canvasHeight,
    imageLeft: builtImage.imageLeft,
    imageTop: builtImage.imageTop,
    imageWidth: builtImage.imageWidth,
    imageHeight: builtImage.imageHeight,
    printOnSideEnabled: builtImage.printOnSideEnabled
  };
}

module.exports = {
  buildMirrorWrapBuffer,
  uploadBufferToS3,
  generateMirrorWrapImage
};