"use client";

import React, { useState, useEffect, useCallback, memo } from "react";
import Image from "next/image";
import { useProviders } from "@/utils/hooks/useProviders";
import {
  fallbackIcon,
  useProviderImages,
} from "@/entities/provider-images/model/useProviderImages";

/*
If the icon is not found, it renders a default unknown icon.
*/

export const WhitestackDynamicImageProviderIcon = (props: any) => {
  const { providerType, src, ...rest } = props;
  const { data: providers } = useProviders();
  const { getImageUrl, blobCache } = useProviderImages();
  const [imageSrc, setImageSrc] = useState<string | undefined>(
    blobCache[providerType] ?? src ?? fallbackIcon
  );

  useEffect(() => {

    const loadImage = async () => {


      setImageSrc(`/whitestack-icons/router.png`);


    };

    loadImage();
  }, [providers, getImageUrl, providerType]);

  if (!imageSrc) return;

  return (
    <Image
      {...rest}
      alt={providerType || "No provider icon found"}
      src={imageSrc}
      onError={() => setImageSrc(fallbackIcon)}
      unoptimized
    />
  );
};
