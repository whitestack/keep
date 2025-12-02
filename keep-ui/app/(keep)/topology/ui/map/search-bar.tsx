import React, { useEffect, useState, useRef } from "react";
import { TextInput } from "@/components/ui";

export type Option<T> = {
  label: string;
  value: T;
};



export function ServiceSearchBar<T>() {
    const [inputValue, setInputValue] = useState("");
    const [filteredOptions, setFilteredOptions] = useState<Option<T>[]>([]);
    const [isOpen, setIsOpen] = useState(false);
    const [focusedIndex, setFocusedIndex] = useState(-1);
    const wrapperRef = useRef<HTMLDivElement | null>(null);
    const inputRef = useRef<HTMLInputElement | null>(null);
    const listRef = useRef<HTMLUListElement | null>(null);

    const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const value = e.target.value;
        setInputValue(value);
    };
    
 
    return (
        <>
        <TextInput
            ref={inputRef}
            value={inputValue}
            onChange={handleInputChange}
            placeholder={'busqueda'}
            aria-autocomplete="list"
            aria-haspopup="listbox"
            aria-expanded={isOpen}
            aria-activedescendant={
            focusedIndex >= 0 ? `option-${focusedIndex}` : undefined
            }
        />
        </>
    );
}
