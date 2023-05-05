﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Controls;

using Microsoft.Toolkit.Mvvm.ComponentModel;

using SpyCore.Contracts.Services;
using SpyCore.ViewModels;
using SpyCore.Views;

namespace SpyCore.Services
{
    public class PageService : IPageService
    {
        private readonly Dictionary<string, Type> _pages = new Dictionary<string, Type>();
        private readonly IServiceProvider _serviceProvider;

        public PageService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
            Configure<MainViewModel, MainPage>();
            Configure<CommunityViewModel, Page1>();
            Configure<SettingsViewModel, SettingsPage>();
        }

        public Type GetPageType(string key)
        {
            Type pageType;
            lock (_pages)
            {
                if (!_pages.TryGetValue(key, out pageType))
                {
                    throw new ArgumentException($"Sahypa tapylmady: {key}. PageService.Configure çagyrmagy ýatdan çykardyňyzmy?");
                }
            }

            return pageType;
        }

        public Page GetPage(string key)
        {
            var pageType = GetPageType(key);
            return _serviceProvider.GetService(pageType) as Page;
        }

        private void Configure<VM, V>()
            where VM : ObservableObject
            where V : Page
        {
            lock (_pages)
            {
                var key = typeof(VM).FullName;
                if (_pages.ContainsKey(key))
                {
                    throw new ArgumentException($"{key} düwmesi eýýäm “PageService” -da düzüldi");
                }

                var type = typeof(V);
                if (_pages.Any(p => p.Value == type))
                {
                    throw new ArgumentException($"Bu görnüş eýýäm {_pages.First(p => p.Value == type).Key} açary bilen düzüldi ");
                }

                _pages.Add(key, type);
            }
        }
    }
}
